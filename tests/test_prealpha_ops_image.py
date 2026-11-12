"""Ops maintenance image recipe: PG16 archive tools from the pinned server image.

The ops image runs ``pg_dump``/``pg_restore`` against production PostgreSQL, so
the client major must match the server major. Debian bookworm's default
``postgresql-client`` is 15 and cannot be matched to a PG16 server by image
configuration alone. Instead this recipe imports exactly those two tools and
their resolved shared-library closure from the same digest-pinned image the local
Compose profile runs.

These checks read the shipped recipe and its operator documentation. They never
run Docker, pull images or build layers; the closure itself is only proven by a
real build, which this repository does not claim to have run.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
DOCKERFILE = ROOT / "Dockerfile.ops"
DOCUMENTATION = ROOT.parent / "docs" / "backend" / "deployment-preparation.md"

# Same digest as the `postgres` service in the root Compose file.
PG16_IMAGE = (
    "postgres:16.13-bookworm@"
    "sha256:472efd9a66f2b2f1a5aeb18b28de74332e6ef88c2b93a1a5d812fb6db67a5f60"
)
BACKEND_IMAGE = "itsm-backend:0.1.0"
CLIENT_ROOT = "/opt/pg16-client"
DONOR_ROOT = "/pg-client"
DONOR_BINDIR = "/usr/lib/postgresql/16/bin"
ARCHIVE_TOOLS = ("pg_dump", "pg_restore")
DONOR_LDD_MARKER = 'ldd "$binary"'
IMAGE_LDD_MARKER = 'ldd "/opt/pg16-client/bin/$tool"'
RELEASE_MARKER = "$tool.wrapper.version"


def _dockerfile() -> str:
    return DOCKERFILE.read_text(encoding="utf-8")


def _instructions(text: str) -> list[str]:
    """Dockerfile instructions with backslash continuations joined."""
    joined: list[str] = []
    buffer = ""
    for line in text.splitlines():
        stripped = line.rstrip()
        if not buffer and (not stripped or stripped.lstrip().startswith("#")):
            continue
        if stripped.endswith("\\"):
            buffer += stripped[:-1] + " "
            continue
        joined.append((buffer + stripped).strip())
        buffer = ""
    if buffer:
        joined.append(buffer.strip())
    return joined


def _stage(text: str, name: str) -> list[str]:
    """Instructions of one named build stage, without its ``FROM`` line."""
    stages: dict[str, list[str]] = {}
    current: str | None = None
    for instruction in _instructions(text):
        if instruction.startswith("FROM "):
            match = re.search(r"\bAS\s+(\S+)$", instruction)
            current = match.group(1) if match else None
            if current:
                stages[current] = []
            continue
        if current:
            stages[current].append(instruction)
    assert name in stages, f"missing build stage {name}: {sorted(stages)}"
    return stages[name]


def _final_stage(text: str) -> list[str]:
    instructions = _instructions(text)
    froms = [index for index, line in enumerate(instructions) if line.startswith("FROM ")]
    assert froms, "the recipe has no FROM"
    return instructions[froms[-1] :]


def _arg_default(text: str, name: str) -> str:
    pattern = re.compile(rf"^ARG {re.escape(name)}=(.*)$", re.MULTILINE)
    matches = pattern.findall(text)
    assert len(matches) == 1, f"expected one defaulted ARG {name}: {matches}"
    return matches[0]


def _root_compose() -> Path | None:
    """The monorepo Compose file, when this checkout is inside the workspace."""
    for parent in ROOT.parents:
        candidate = parent / "compose.yaml"
        if candidate.is_file():
            return candidate
    return None


def _compose_pg_image(compose: Path) -> str:
    text = compose.read_text(encoding="utf-8")
    matches = re.findall(r"^\s+image:\s*(postgres:[^\s#]+)\s*$", text, re.MULTILINE)
    assert len(matches) == 1, matches
    return matches[0]


def _run_containing(marker: str) -> str:
    """The single shipped ``RUN`` instruction containing ``marker``."""
    matches = [
        instruction
        for instruction in _instructions(_dockerfile())
        if instruction.startswith("RUN ") and marker in instruction
    ]
    assert len(matches) == 1, matches
    return matches[0]


def _write_tool(path: Path, body: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("#!/bin/sh\n" + body, encoding="utf-8")
    path.chmod(0o755)
    return path


def _execute(
    tmp_path: Path,
    *,
    marker: str,
    replacements: list[tuple[str, str]],
    tools: Path,
) -> subprocess.CompletedProcess[str]:
    """Execute the shipped shell fragment with only ``tools`` ahead of the system.

    Every absolute path the fragment writes to or reads from is redirected into
    ``tmp_path``, so the test never touches the real ``/tmp`` or client tree.
    """
    fragment = _run_containing(marker)[len("RUN ") :]
    for old, new in replacements:
        fragment = fragment.replace(old, new)
    environment = {"PATH": f"{tools}:/usr/bin:/bin", "HOME": str(tmp_path)}
    return subprocess.run(
        ["sh", "-c", fragment], capture_output=True, text=True, env=environment, check=False
    )


def _donor_environment(
    tmp_path: Path, *, ldd_body: str | None = None, bindir: str = "regular"
) -> tuple[Path, list[tuple[str, str]]]:
    """A donor stand-in whose PATH ``pg_dump`` is a pg_wrapper-style script.

    The real versioned binaries live in ``versioned-bin``; only that directory is
    meant to be selected. ``bindir`` models the regular, missing and symlinked
    states of the versioned binary.
    """
    client = tmp_path / "client"
    (client / "bin").mkdir(parents=True)
    (client / "lib").mkdir(parents=True)
    library = tmp_path / "donor-lib" / "libz.so.1"
    library.parent.mkdir(parents=True)
    library.write_bytes(b"fake shared library")
    tools = tmp_path / "tools"
    versioned = tmp_path / "versioned-bin"
    versioned.mkdir()
    real = 'echo "pg_dump (PostgreSQL) 16.13 (Debian 16.13-1.pgdg12+1)"\n'
    for tool in ARCHIVE_TOOLS:
        _write_tool(tools / tool, f'echo "{tool} (PostgreSQL) 16.1 (Debian 16.1-1)"\n')
        path = versioned / tool
        if bindir == "regular":
            _write_tool(path, f'echo "{tool} (PostgreSQL) 16.13 (Debian 16.13-1.pgdg12+1)"\n')
        elif bindir == "symlink":
            wrapper = tmp_path / f"pg_wrapper-{tool}"
            _write_tool(wrapper, real)
            path.symlink_to(wrapper)
    body = ldd_body
    if body is None:
        body = f'echo "libz.so.1 => {library} (0x00007f0000000000)"\n'
    _write_tool(tools / "ldd", body)
    return tools, [
        ("/tmp/", f"{tmp_path}/"),
        (DONOR_BINDIR, str(versioned)),
        (DONOR_ROOT, str(client)),
    ]


def _image_ldd_environment(tmp_path: Path, *, ldd_body: str) -> tuple[Path, list[tuple[str, str]]]:
    client = tmp_path / "client"
    (client / "bin").mkdir(parents=True)
    for tool in ARCHIVE_TOOLS:
        _write_tool(client / "bin" / tool, "exit 0\n")
    tools = tmp_path / "tools"
    _write_tool(tools / "ldd", ldd_body)
    return tools, [("/tmp/", f"{tmp_path}/"), (CLIENT_ROOT, str(client))]


def _release_environment(tmp_path: Path, version: str) -> tuple[Path, list[tuple[str, str]]]:
    client = tmp_path / "client"
    (client / "bin").mkdir(parents=True)
    wrappers = tmp_path / "local-bin"
    wrappers.mkdir()
    for tool in ARCHIVE_TOOLS:
        body = f'echo "{tool} (PostgreSQL) {version} (Debian {version}-1.pgdg120+1)"\n'
        _write_tool(client / "bin" / tool, body)
        _write_tool(wrappers / tool, body)
    tools = tmp_path / "tools"
    tools.mkdir()
    return tools, [
        ("/tmp/", f"{tmp_path}/"),
        (CLIENT_ROOT, str(client)),
        ("/usr/local/bin", str(wrappers)),
    ]


def test_the_client_donor_is_the_compose_pinned_postgres_image() -> None:
    text = _dockerfile()

    assert _arg_default(text, "POSTGRES_CLIENT_IMAGE") == PG16_IMAGE
    assert re.search(r"@sha256:[0-9a-f]{64}$", PG16_IMAGE)
    assert "FROM ${POSTGRES_CLIENT_IMAGE} AS pg-client" in text

    compose = _root_compose()
    if compose is None:  # pragma: no cover - standalone backend checkout
        pytest.skip("root compose.yaml is outside this checkout")
    assert _compose_pg_image(compose) == PG16_IMAGE


def test_the_donor_exports_only_the_archive_tools_and_their_library_closure() -> None:
    donor = _stage(_dockerfile(), "pg-client")
    run = " ".join(instruction for instruction in donor if instruction.startswith("RUN "))

    for tool in ARCHIVE_TOOLS:
        assert tool in run
    # Exactly the two tools the ops code invokes; psql is never called.
    assert re.search(r"for tool in pg_dump pg_restore; do", run)
    assert "psql" not in run
    # The real binaries and their ldd-resolved closure go to a dedicated tree.
    assert "ldd" in run
    assert "not found" in run and "exit 1" in run
    assert f'mkdir -p "{DONOR_ROOT}/bin" "{DONOR_ROOT}/lib"' in run
    assert "cp -L" in run and f"{DONOR_ROOT}/lib/" in run
    # Nothing from the donor's package manager, server or data directory is used.
    assert not any("apt-get" in instruction for instruction in donor)
    assert "/var/lib/postgresql" not in "\n".join(donor)
    assert "COPY --from=pg-client" not in "\n".join(donor)


def test_the_donor_proves_the_postgres_major_before_exporting_it() -> None:
    donor = _stage(_dockerfile(), "pg-client")
    run = " ".join(instruction for instruction in donor if instruction.startswith("RUN "))

    assert "/pg-client/bin/pg_dump --version" in run
    assert "/pg-client/bin/pg_restore --version" in run
    assert run.count("16\\.13") >= 2
    assert run.count("exit 1") >= 2


def test_the_debian_postgresql_client_package_is_removed() -> None:
    text = _dockerfile()

    assert "postgresql-client" not in text
    installs = [line for line in _instructions(text) if "apt-get install" in line]
    assert len(installs) == 1, installs
    assert "mariadb-client" in installs[0]
    assert "unixodbc" in installs[0]
    # MSSQL stays an explicitly supplied licensed variant, never bundled here.
    executed = "\n".join(_instructions(text))
    assert "sqlcmd" not in executed


def test_the_backend_runtime_contract_is_retained() -> None:
    text = _dockerfile()
    final = _final_stage(text)

    assert final[0] == f"FROM {BACKEND_IMAGE}"
    assert "USER 10001:10001" in final
    assert final[-1] == 'CMD ["python", "-m", "itsm.deployment", "backup-loop"]'
    install = next(line for line in final if "apt-get install" in line)
    assert "chown 10001:10001 /data/backups" in install
    assert "mkdir -p /data/backups" in install
    # The imported client lives outside every interpreter and system path.
    assert f"COPY --from=pg-client {DONOR_ROOT} {CLIENT_ROOT}" in final
    assert "USER root" in final
    assert final.index("USER root") < final.index("USER 10001:10001")


def test_the_pg16_libraries_are_scoped_to_a_wrapper_not_a_global_path() -> None:
    text = _dockerfile()
    final = _final_stage(text)

    assert not re.search(r"^ENV\b.*LD_LIBRARY_PATH", text, re.MULTILINE)
    assert "ldconfig" not in text
    # Copying all of /usr/lib is what "donor" must never mean.
    assert "/usr/local/lib" not in text
    assert not re.search(r"COPY --from=pg-client /usr/(lib|local|share)", text)

    wrappers = [line for line in final if "printf" in line or "LD_LIBRARY_PATH" in line]
    assert wrappers, "the wrapper instruction is missing"
    wrapper = " ".join(wrappers)
    assert f"LD_LIBRARY_PATH={CLIENT_ROOT}/lib" in wrapper
    assert "exec " in wrapper and "pg_dump" in wrapper and "pg_restore" in wrapper
    assert '> "/usr/local/bin/$tool"' in wrapper
    assert "chmod 0755" in wrapper


def test_the_final_image_fails_closed_when_the_client_cannot_run() -> None:
    final = " ".join(line for line in _final_stage(_dockerfile()) if line.startswith("RUN "))

    # Unresolved libraries or a wrong major must break the build, not the backup.
    assert re.search(r"ldd .*grep -q 'not found'", final)
    assert f"{CLIENT_ROOT}/bin/pg_dump --version" in final
    assert f"{CLIENT_ROOT}/bin/pg_restore --version" in final
    assert final.count("pg_dump --version") >= 1
    assert final.count("pg_restore --version") >= 1
    assert '"/usr/local/bin/$tool" --version' in final
    assert final.count("16\\.13") >= 2
    assert final.count("exit 1") >= 2


def test_the_donor_no_longer_hides_pipeline_failures() -> None:
    donor = _run_containing(DONOR_LDD_MARKER)

    # The old recipe piped cat|awk|sort into `while read`; only the loop status
    # survived. Every source step is now a checked command on its own file.
    assert "| while" not in donor
    assert "done < /tmp/client.unique-paths" in donor or "done < " in donor
    for anchor in ("cat /tmp/pg_dump.ldd", "awk '/=> ", "sort -u"):
        start = donor.index(anchor)
        window = donor[start : start + 240]
        assert "|| {" in window and "exit 1" in window, anchor


def test_the_donor_run_refuses_a_failed_ldd(tmp_path: Path) -> None:
    tools, replacements = _donor_environment(tmp_path, ldd_body="exit 1\n")

    result = _execute(tmp_path, marker=DONOR_LDD_MARKER, replacements=replacements, tools=tools)

    assert result.returncode != 0, result.stdout
    assert "ldd failed for pg_dump" in result.stderr


def test_the_donor_run_accepts_a_resolved_closure(tmp_path: Path) -> None:
    tools, replacements = _donor_environment(tmp_path)

    result = _execute(tmp_path, marker=DONOR_LDD_MARKER, replacements=replacements, tools=tools)

    assert result.returncode == 0, result.stderr
    assert (tmp_path / "client" / "bin" / "pg_dump").is_file()
    assert (tmp_path / "client" / "lib" / "libz.so.1").read_bytes() == b"fake shared library"


def test_the_donor_does_not_resolve_the_tools_through_path() -> None:
    donor = _run_containing(DONOR_LDD_MARKER)

    # Debian's /usr/bin/pg_dump is a pg_wrapper script, not an ELF binary, and
    # `ldd` refuses it. The versioned path is selected explicitly.
    assert "command -v" not in donor
    assert f'binary="{DONOR_BINDIR}/$tool"' in donor
    assert '[ -L "$binary" ]' in donor
    assert "not a regular donor file" in donor


def test_the_donor_selects_the_versioned_binary_not_the_path_wrapper(tmp_path: Path) -> None:
    tools, replacements = _donor_environment(tmp_path)

    result = _execute(tmp_path, marker=DONOR_LDD_MARKER, replacements=replacements, tools=tools)

    assert result.returncode == 0, result.stderr
    versioned = tmp_path / "versioned-bin" / "pg_dump"
    copied = tmp_path / "client" / "bin" / "pg_dump"
    assert copied.read_bytes() == versioned.read_bytes()
    # The PATH script stays a 16.1 wrapper and must not have been selected.
    assert "16.1-1" not in copied.read_text()
    assert copied.read_bytes() != (tmp_path / "tools" / "pg_dump").read_bytes()


def test_the_donor_refuses_a_missing_versioned_binary(tmp_path: Path) -> None:
    tools, replacements = _donor_environment(tmp_path, bindir="missing")

    result = _execute(tmp_path, marker=DONOR_LDD_MARKER, replacements=replacements, tools=tools)

    assert result.returncode != 0, result.stdout
    assert "not a regular donor file" in result.stderr


def test_the_donor_refuses_a_symlinked_donor_binary(tmp_path: Path) -> None:
    tools, replacements = _donor_environment(tmp_path, bindir="symlink")

    result = _execute(tmp_path, marker=DONOR_LDD_MARKER, replacements=replacements, tools=tools)

    assert result.returncode != 0, result.stdout
    assert "not a regular donor file" in result.stderr


@pytest.mark.parametrize("step", ["cat", "awk", "sort"])
def test_the_donor_run_refuses_a_failed_extraction_step(tmp_path: Path, step: str) -> None:
    tools, replacements = _donor_environment(tmp_path)
    _write_tool(tools / step, "exit 3\n")

    result = _execute(tmp_path, marker=DONOR_LDD_MARKER, replacements=replacements, tools=tools)

    assert result.returncode != 0, result.stdout
    assert "could not" in result.stderr


def test_the_ldd_report_step_refuses_a_failed_ldd(tmp_path: Path) -> None:
    tools, replacements = _image_ldd_environment(tmp_path, ldd_body="exit 1\n")

    result = _execute(tmp_path, marker=IMAGE_LDD_MARKER, replacements=replacements, tools=tools)

    # A failing ldd with no output must not read as "no unresolved library".
    assert result.returncode != 0, result.stdout
    assert "ldd failed for pg_dump" in result.stderr


def test_the_ldd_report_step_refuses_an_unresolved_library(tmp_path: Path) -> None:
    tools, replacements = _image_ldd_environment(
        tmp_path, ldd_body='echo "libpq.so.5 => not found"\n'
    )

    result = _execute(tmp_path, marker=IMAGE_LDD_MARKER, replacements=replacements, tools=tools)

    assert result.returncode != 0, result.stdout
    assert "unresolved shared library for pg_dump" in result.stderr


def test_the_ldd_report_step_accepts_a_resolved_closure(tmp_path: Path) -> None:
    tools, replacements = _image_ldd_environment(
        tmp_path,
        ldd_body='echo "libpq.so.5 => /usr/lib/x86_64-linux-gnu/libpq.so.5 (0x00007f0000000000)"\n',
    )

    result = _execute(tmp_path, marker=IMAGE_LDD_MARKER, replacements=replacements, tools=tools)

    assert result.returncode == 0, result.stderr


def test_the_release_check_accepts_the_exact_16_13_release(tmp_path: Path) -> None:
    tools, replacements = _release_environment(tmp_path, "16.13")

    result = _execute(tmp_path, marker=RELEASE_MARKER, replacements=replacements, tools=tools)

    assert result.returncode == 0, result.stderr


def test_the_release_check_refuses_a_16_14_client(tmp_path: Path) -> None:
    tools, replacements = _release_environment(tmp_path, "16.14")

    result = _execute(tmp_path, marker=RELEASE_MARKER, replacements=replacements, tools=tools)

    # The pinned release, not just major 16, is what these backups are proven for.
    assert result.returncode != 0, result.stdout
    assert "16.13 release" in result.stderr


def test_the_documentation_states_the_image_compatibility_limit() -> None:
    documentation = DOCUMENTATION.read_text(encoding="utf-8")
    section = documentation.split("`Dockerfile.ops` is a separate maintenance image", 1)[1]

    assert PG16_IMAGE in section
    assert "pg_dump" in section and "pg_restore" in section
    assert "ldd" in section
    assert "16.13" in section
    # The pinned release, not only the major, is the compatibility requirement.
    assert "exact" in section.lower()
    assert "16.14" in section
    assert "refuse" in section.lower()
    # No claim of full reproducibility or a performed build/probe.
    assert "no image build" in section.lower() or "not executed" in section.lower()
    assert "reproducib" in section.lower()
