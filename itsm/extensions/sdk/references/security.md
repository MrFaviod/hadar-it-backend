# Isolation model and permissions (SDK v2)

SDK v2 replaces "trusted native code" with verifiable technical isolation. The
guarantees below are enforced by kernel mechanisms and by the host, not by
documentation, and they are covered by tests that run real sandboxed probes.

## Boundaries

| Phase | Boundary |
| --- | --- |
| Development and validation | Candidate bytes run only in the fixed offline validator container. |
| Installed, `sandboxed` | Each invocation is a separate restricted process; the API/worker never imports module code. |
| Installed, `declarative` | No module code exists; the host executes declared operations against the module file. |
| Core data | Reachable only through authorized host capabilities using the invoking principal. |

## Sandbox mechanisms

Before the runner imports module code it applies:

1. **rlimits** — CPU seconds, address space, file size, open files, and
   `RLIMIT_CORE=0`.
2. **`PR_SET_NO_NEW_PRIVS`** — no setuid/setgid escalation.
3. **Landlock** — filesystem ruleset (syscalls 444/445/446): read+execute for
   the standard library, shared libraries, the runner directory, `/usr`,
   `/lib`, `/etc/ld.so.cache`, `/dev/null`, `/dev/urandom`, and the read-only
   package cache; read+write **only** inside the module data directory. When
   ABI ≥ 4 the ruleset also handles TCP `bind`/`connect` (denied). When ABI ≥ 6
   it scopes abstract UNIX sockets and signals.
4. **seccomp-bpf** (`prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER)`) — x86_64 and
   aarch64 arch check (any other arch is killed), deny-list returning `EPERM`
   for `socket`, `socketpair`, `execve`, `execveat`, `ptrace`,
   `process_vm_readv/writev`, `unshare`, `setns`, `mount`, `umount2`,
   `pivot_root`, `chroot`, `bpf`, `keyctl`, `add_key`, `request_key`,
   `perf_event_open`, `kexec_load`, `kexec_file_load`, `init_module`,
   `finit_module`, `delete_module`, `open_by_handle_at` and the `io_uring`
   family; `clone` only with `CLONE_THREAD`; `clone3` returns `ENOSYS`.

If the architecture is unknown or the Landlock ABI is below 4, installation and
invocation fail closed with `sandbox_unavailable` (HTTP 503). Declarative
modules are unaffected because they never spawn a process.

## Host-side limits

The host enforces a wall-clock timeout, a 1 MiB total output cap, a 1 MiB
per-line cap, at most 200 capability calls per invocation, and kills the whole
process group on timeout or cap violation. The module runs with an empty
environment: no `ITSM_*` variable, database URL, token or secret is visible.
stdout/stderr of module code are redirected away from the protocol channel.

## What this does not promise

- It is not a proof against kernel or hypervisor compromise. Landlock ABI and
  seccomp coverage depend on the host kernel; this workstation reports Landlock
  ABI 10, other hosts may be lower and then fail closed.
- Side channels (timing, memory pressure) are not mitigated.
- The package cache is read-only but shared per digest across modules with the
  same bytes; module code cannot write to it, only read its own files.
- Validator container isolation and sandbox isolation are separate mechanisms;
  a passing validation is not a sandbox attestation.
- Data is kept on disable and uninstall. Purge is a separate explicit action
  with typed confirmation and is not part of this SDK.

## Permissions

- Declared extension permissions use `ext_<id_with_underscores>.<suffix>`.
- Every operation checks its declared permission; the host also checks module
  enabled state and canonical core permissions.
- `corePermissions` are existing core codes, granted only as an explicit
  installation policy effect to the Superadmin role. There are no implicit
  admin, user, machine or wildcard grants.
- Capability calls always run with the invoking principal through the canonical
  services, so Casbin authorization is never bypassed by using the extension
  path.
- HTTP mutations require the authenticated session, Origin/CSRF validation and
  the trusted principal. Bearer identities are resolved by the host.
- Chat, MCP and HTTP invoke the same operation handler and authorization path.
- Machine actors cannot approve, enable, roll back, uninstall or install.

## Package safety

Rejected before any execution:

- absolute paths, `..`, backslashes, NUL/control characters, drive letters;
- symlinks, special files, encrypted ZIP entries and unsupported compression;
- duplicate or case-colliding paths;
- unknown files outside the package contract;
- oversize archive, expanded tree, entry count or single file;
- missing `extension.json`, a `backend.py` that the declared runtime forbids or
  requires, declared skill paths, or at least one `tests/*.py`;
- unsupported dependencies, package-manager files and native binaries;
- blocked imports/calls (`itsm`, `sqlalchemy`, `socket`, `subprocess`, `ctypes`,
  `multiprocessing`, relative imports, `os.system`-style process spawning),
  reported as `contract_gap_required:` with the missing capability named;
- a manifest that fails the canonical schema or semantic checks;
- any declared operation not bound by `register(sdk)`.

Never trust a client-supplied digest, validation result, permission delta,
migration plan or package path. The host recomputes the digest, binds the
server-owned validation report, and derives the delta from the immutable
manifest.

## Human approval

Only a persisted human Superadmin can approve, enable, disable, roll back or
uninstall. A chat message such as "yes, install it" is not approval. Agent
responses must return a pending review and the exact human UI path. Missing
contracts must be recorded as an `extension_contract_gap`, never worked around
by touching private core structures.
