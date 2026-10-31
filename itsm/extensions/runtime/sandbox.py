"""Kernel isolation applied by the runner before module code is imported.

Three independent mechanisms are stacked, each failing closed:

* resource limits (CPU, address space, file size, open files, no core dump);
* no_new_privs plus a Landlock ruleset that grants read/execute on interpreter
  and package paths and read/write only on the module data directory, denies
  TCP bind/connect and scopes abstract unix sockets and signals on ABI >= 6;
* a seccomp-BPF filter that refuses a documented syscall deny-list with EPERM,
  allows ``clone`` only with ``CLONE_THREAD`` and answers ``clone3`` with ENOSYS.
  The deny-list includes the inode metadata family (``chmod``/``utime``/xattr):
  Landlock restricts file content, not ownership-based metadata changes, and a
  module runs as the service user.  Without this entry a module could make the
  core database unreadable (``chmod 000``) or tamper with a foreign module's
  directories, so the runner refuses the whole family it never needs.

Stdlib only: this file is imported by ``python -I -S -B runner.py``.
"""

from __future__ import annotations

import ctypes
import errno
import os
import platform
import resource
import stat
import struct
import sys
from pathlib import Path

PR_SET_NO_NEW_PRIVS = 38
PR_SET_SECCOMP = 22
SECCOMP_MODE_FILTER = 2
SECCOMP_RET_KILL_PROCESS = 0x80000000
SECCOMP_RET_ALLOW = 0x7FFF0000
SECCOMP_RET_ERRNO = 0x00050000
CLONE_THREAD = 0x00010000
LANDLOCK_CREATE_RULESET_VERSION = 1
LANDLOCK_RULE_PATH_BENEATH = 1
SYS_LANDLOCK_CREATE_RULESET = 444
SYS_LANDLOCK_ADD_RULE = 445
SYS_LANDLOCK_RESTRICT_SELF = 446
ARCH_AUDIT = {"x86_64": 0xC000003E, "aarch64": 0xC00000B7}

# Syscall numbers for the two arches the host supports.  Anything else fails
# closed: a guessed table would be a silent hole.
DENY_SYSCALLS = {
    "x86_64": {
        "socket": 41,
        "socketpair": 53,
        "execve": 59,
        "execveat": 322,
        "ptrace": 101,
        "process_vm_readv": 310,
        "process_vm_writev": 311,
        "unshare": 272,
        "setns": 308,
        "mount": 165,
        "umount2": 166,
        "pivot_root": 155,
        "chroot": 161,
        "bpf": 321,
        "keyctl": 250,
        "add_key": 248,
        "request_key": 249,
        "perf_event_open": 298,
        "kexec_load": 246,
        "kexec_file_load": 320,
        "init_module": 175,
        "finit_module": 313,
        "delete_module": 176,
        "open_by_handle_at": 304,
        "io_uring_setup": 425,
        "io_uring_enter": 426,
        "io_uring_register": 427,
        "chmod": 90,
        "fchmod": 91,
        "fchmodat": 268,
        "fchmodat2": 452,
        "utime": 132,
        "utimes": 235,
        "futimesat": 261,
        "utimensat": 280,
        "setxattr": 188,
        "lsetxattr": 189,
        "fsetxattr": 190,
        "getxattr": 191,
        "lgetxattr": 192,
        "fgetxattr": 193,
        "listxattr": 194,
        "llistxattr": 195,
        "flistxattr": 196,
        "removexattr": 197,
        "lremovexattr": 198,
        "fremovexattr": 199,
    },
    "aarch64": {
        "socket": 198,
        "socketpair": 199,
        "execve": 221,
        "execveat": 281,
        "ptrace": 117,
        "process_vm_readv": 270,
        "process_vm_writev": 271,
        "unshare": 97,
        "setns": 268,
        "mount": 40,
        "umount2": 39,
        "pivot_root": 41,
        "chroot": 51,
        "bpf": 280,
        "keyctl": 219,
        "add_key": 217,
        "request_key": 218,
        "perf_event_open": 241,
        "kexec_load": 104,
        "kexec_file_load": 294,
        "init_module": 105,
        "finit_module": 273,
        "delete_module": 106,
        "open_by_handle_at": 265,
        "io_uring_setup": 425,
        "io_uring_enter": 426,
        "io_uring_register": 427,
        # aarch64 has no chmod/utime/utimes: glibc routes them through the
        # *at variants, which are denied here along with fchmodat2.
        "fchmod": 52,
        "fchmodat": 53,
        "fchmodat2": 452,
        "utimensat": 88,
        "setxattr": 5,
        "lsetxattr": 6,
        "fsetxattr": 7,
        "getxattr": 8,
        "lgetxattr": 9,
        "fgetxattr": 10,
        "listxattr": 11,
        "llistxattr": 12,
        "flistxattr": 13,
        "removexattr": 14,
        "lremovexattr": 15,
        "fremovexattr": 16,
    },
}
CLONE_NR = {"x86_64": 56, "aarch64": 220}
CLONE3_NR = {"x86_64": 435, "aarch64": 435}


class SandboxUnavailable(RuntimeError):
    """The host kernel cannot provide the isolation this runtime requires."""


def detected_arch() -> str:
    return platform.machine()


def _libc() -> ctypes.CDLL:
    library = ctypes.CDLL(None, use_errno=True)
    library.syscall.restype = ctypes.c_long
    library.prctl.restype = ctypes.c_int
    return library


def detect_landlock_abi() -> int:
    """Return the Landlock ABI version, or 0 when the syscall is unavailable."""
    if detected_arch() not in ARCH_AUDIT:
        return 0
    library = _libc()
    result = library.syscall(
        ctypes.c_long(SYS_LANDLOCK_CREATE_RULESET),
        ctypes.c_void_p(0),
        ctypes.c_size_t(0),
        ctypes.c_uint32(LANDLOCK_CREATE_RULESET_VERSION),
    )
    return int(result) if result > 0 else 0


def availability() -> dict[str, object]:
    """Describe the sandbox this kernel can offer without mutating anything."""
    arch = detected_arch()
    abi = detect_landlock_abi()
    if arch not in ARCH_AUDIT:
        detail = f"unsupported architecture: {arch}"
    elif abi < 4:
        detail = f"Landlock ABI {abi} is older than the required ABI 4"
    else:
        detail = "landlock + seccomp-bpf runner available"
    return {
        "available": arch in ARCH_AUDIT and abi >= 4,
        "landlockAbi": abi or None,
        "arch": arch,
        "detail": detail,
    }


def _set_limit(kind: int, value: int) -> None:
    try:
        resource.setrlimit(kind, (value, value))
    except (ValueError, OSError) as exc:  # pragma: no cover - kernel dependent
        raise SandboxUnavailable(f"cannot set {kind}: {exc}") from None


def apply_limits(
    *,
    cpu_seconds: int,
    memory_mb: int,
    file_size_bytes: int,
    open_files: int,
) -> None:
    """Bound CPU time, address space, file size, descriptors and core dumps."""
    _set_limit(resource.RLIMIT_CORE, 0)
    _set_limit(resource.RLIMIT_CPU, int(cpu_seconds))
    _set_limit(resource.RLIMIT_AS, int(memory_mb) * 1024 * 1024)
    _set_limit(resource.RLIMIT_FSIZE, int(file_size_bytes))
    _set_limit(resource.RLIMIT_NOFILE, int(open_files))


def no_new_privs() -> None:
    library = _libc()
    if library.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        raise SandboxUnavailable(f"PR_SET_NO_NEW_PRIVS failed: {os.strerror(ctypes.get_errno())}")


def _fs_access(abi: int) -> int:
    access = 0x1FFF  # EXECUTE..MAKE_SYM
    if abi >= 2:
        access |= 1 << 13  # REFER
    if abi >= 3:
        access |= 1 << 14  # TRUNCATE
    if abi >= 5:
        access |= 1 << 15  # IOCTL_DEV
    return access


class _RulesetAttr(ctypes.Structure):
    _fields_ = [
        ("handled_access_fs", ctypes.c_uint64),
        ("handled_access_net", ctypes.c_uint64),
        ("scoped", ctypes.c_uint64),
    ]


class _PathBeneathAttr(ctypes.Structure):
    _fields_ = [("allowed_access", ctypes.c_uint64), ("parent_fd", ctypes.c_int32)]


def apply_landlock(
    *,
    read_paths: list[str],
    write_paths: list[str],
    abi: int,
) -> None:
    """Restrict the filesystem view and deny TCP bind/connect."""
    if abi < 4:
        raise SandboxUnavailable(f"Landlock ABI {abi} cannot restrict network access")
    library = _libc()
    handled_fs = _fs_access(abi)
    attr = _RulesetAttr()
    attr.handled_access_fs = handled_fs
    attr.handled_access_net = 0b11  # BIND_TCP | CONNECT_TCP
    attr.scoped = 0
    if abi >= 6:
        attr.scoped = 0b11  # ABSTRACT_UNIX_SOCKET | SIGNAL
    size = 8 if abi < 4 else 16 if abi < 6 else 24
    ruleset_fd = library.syscall(
        ctypes.c_long(SYS_LANDLOCK_CREATE_RULESET),
        ctypes.byref(attr),
        ctypes.c_size_t(size),
        ctypes.c_uint32(0),
    )
    if ruleset_fd < 0:
        raise SandboxUnavailable(
            f"landlock_create_ruleset failed: {os.strerror(ctypes.get_errno())}"
        )
    try:
        read_access = (1 << 0) | (1 << 2) | (1 << 3)  # EXECUTE | READ_FILE | READ_DIR
        for path in read_paths:
            _add_path_rule(library, int(ruleset_fd), path, read_access)
        for path in write_paths:
            _add_path_rule(library, int(ruleset_fd), path, handled_fs)
        if (
            library.syscall(
                ctypes.c_long(SYS_LANDLOCK_RESTRICT_SELF),
                ctypes.c_int(ruleset_fd),
                ctypes.c_uint32(0),
            )
            != 0
        ):
            raise SandboxUnavailable(
                f"landlock_restrict_self failed: {os.strerror(ctypes.get_errno())}"
            )
    finally:
        os.close(int(ruleset_fd))


def _add_path_rule(library: ctypes.CDLL, ruleset_fd: int, path: str, access: int) -> None:
    try:
        descriptor = os.open(path, os.O_PATH | os.O_CLOEXEC)
        is_directory = stat.S_ISDIR(os.fstat(descriptor).st_mode)
    except OSError:
        return  # absent optional path (e.g. /etc/ld.so.cache on some images)
    if not is_directory:
        # Landlock rejects directory-only access bits on a regular file or device.
        access &= (1 << 0) | (1 << 1) | (1 << 2) | (1 << 14)
    try:
        rule = _PathBeneathAttr()
        rule.allowed_access = access
        rule.parent_fd = descriptor
        if (
            library.syscall(
                ctypes.c_long(SYS_LANDLOCK_ADD_RULE),
                ctypes.c_int(ruleset_fd),
                ctypes.c_int(LANDLOCK_RULE_PATH_BENEATH),
                ctypes.byref(rule),
                ctypes.c_uint32(0),
            )
            != 0
        ):
            raise SandboxUnavailable(
                f"landlock_add_rule({path}) failed: {os.strerror(ctypes.get_errno())}"
            )
    finally:
        os.close(descriptor)


def _bpf(code: int, jt: int, jf: int, k: int) -> bytes:
    return struct.pack("<HBBI", code, jt, jf, k & 0xFFFFFFFF)


def build_seccomp_program(arch: str) -> tuple[bytes, int]:
    """Assemble the deny-list filter for one architecture."""
    if arch not in ARCH_AUDIT:
        raise SandboxUnavailable(f"unsupported architecture: {arch}")
    deny = DENY_SYSCALLS[arch]
    retire_errno = SECCOMP_RET_ERRNO | errno.EPERM
    clone_nr = CLONE_NR[arch]
    clone3_nr = CLONE3_NR[arch]
    instructions = [
        _bpf(0x20, 0, 0, 4),  # A = arch
        _bpf(0x15, 1, 0, ARCH_AUDIT[arch]),
        _bpf(0x06, 0, 0, SECCOMP_RET_KILL_PROCESS),
        _bpf(0x20, 0, 0, 0),  # A = syscall number
    ]
    for number in deny.values():
        instructions.append(_bpf(0x15, 0, 1, number))
        instructions.append(_bpf(0x06, 0, 0, retire_errno))
    instructions.extend(
        [
            _bpf(0x15, 0, 3, clone_nr),
            _bpf(0x20, 0, 0, 16),  # A = low word of args[0]
            _bpf(0x45, 1, 0, CLONE_THREAD),
            _bpf(0x06, 0, 0, retire_errno),
            _bpf(0x15, 0, 1, clone3_nr),
            _bpf(0x06, 0, 0, SECCOMP_RET_ERRNO | errno.ENOSYS),
            _bpf(0x06, 0, 0, SECCOMP_RET_ALLOW),
        ]
    )
    return b"".join(instructions), len(instructions)


class _SockFilter(ctypes.Structure):
    _fields_ = [
        ("code", ctypes.c_uint16),
        ("jt", ctypes.c_uint8),
        ("jf", ctypes.c_uint8),
        ("k", ctypes.c_uint32),
    ]


class _SockFprog(ctypes.Structure):
    _fields_ = [
        ("len", ctypes.c_uint16),
        ("filter", ctypes.POINTER(_SockFilter)),
    ]


def apply_seccomp(arch: str | None = None) -> None:
    """Install the deny-list filter through PR_SET_SECCOMP."""
    machine = arch or detected_arch()
    raw, count = build_seccomp_program(machine)
    filters = (_SockFilter * count)()
    for index in range(count):
        chunk = raw[index * 8 : index * 8 + 8]
        code, jt, jf, k = struct.unpack("<HBBI", chunk)
        filters[index] = _SockFilter(code, jt, jf, k)
    program = _SockFprog(count, filters)
    library = _libc()
    if library.prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, ctypes.byref(program), 0, 0) != 0:
        raise SandboxUnavailable(f"PR_SET_SECCOMP failed: {os.strerror(ctypes.get_errno())}")


def default_read_paths(package_dir: str, runner_dir: str) -> list[str]:
    """Interpreter, shared-library and package paths the runner may read."""
    candidates: list[str] = [package_dir, runner_dir]
    for key in ("stdlib", "platstdlib", "purelib", "platlib"):
        try:
            import sysconfig

            value = sysconfig.get_paths().get(key)
        except ImportError, KeyError, AttributeError:  # pragma: no cover
            value = None
        if value:
            candidates.append(value)
    candidates.extend(
        [
            str(Path(sys.base_prefix) / "lib"),
            str(Path(sys.prefix) / "lib"),
            sys.base_prefix,
            "/usr",
            "/usr/lib",
            "/usr/lib64",
            "/usr/share",
            "/lib",
            "/lib64",
            "/etc/ld.so.cache",
            "/etc/localtime",
            "/dev/urandom",
            "/dev/null",
        ]
    )
    unique: list[str] = []
    seen: set[str] = set()
    for path in candidates:
        if path not in seen and Path(path).exists():
            seen.add(path)
            unique.append(path)
    return unique


def enforce(
    *,
    read_paths: list[str],
    data_dir: str,
    cpu_seconds: int,
    memory_mb: int,
    file_size_bytes: int,
    open_files: int,
) -> None:
    """Apply every mechanism in order; any unsupported primitive fails closed."""
    abi = detect_landlock_abi()
    if abi < 4:
        raise SandboxUnavailable(
            f"Landlock ABI {abi} is not supported; module execution is refused"
        )
    apply_limits(
        cpu_seconds=cpu_seconds,
        memory_mb=memory_mb,
        file_size_bytes=file_size_bytes,
        open_files=open_files,
    )
    no_new_privs()
    apply_landlock(read_paths=read_paths, write_paths=[data_dir], abi=abi)
    apply_seccomp()
