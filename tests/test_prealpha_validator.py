"""Public validator-image recipe: no private base or machine-specific ID default.

`Dockerfile.extension-validator` must reuse the operator-built public backend
image and a caller-supplied, locally inspected base ID. These checks read the
shipped recipe and its operator documentation only; they never run Docker, pull
images or build layers.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DOCKERFILE = ROOT / "Dockerfile.extension-validator"
SDK_DOC = ROOT / "docs" / "extensions-sdk.md"

BUN_DIGEST = "oven/bun@sha256:9114c058aeae42162ee16dd5084b95fe9473970bb6bcb5b232ab1630f0546895"
PUBLIC_BASE = "itsm-backend:0.1.0"
PRIVATE_BASE = "itsm-phase11-backend:verification"
HOST_SPECIFIC_ID = "sha256:c3b29b814929ab5107c91ecf042d3830b25d0380b2d72d9c87274441a556529f"


def _dockerfile() -> str:
    return DOCKERFILE.read_text(encoding="utf-8")


def _operator_section() -> str:
    doc = SDK_DOC.read_text(encoding="utf-8")
    assert "## Operator: prepare the offline validator image" in doc
    return doc.split("## Operator: prepare the offline validator image", 1)[1].split("\n## ", 1)[0]


def _declarations(text: str, name: str) -> list[str]:
    """Every ``ARG <name>`` / ``ARG <name>=default`` line, in file order."""
    pattern = re.compile(rf"^ARG {re.escape(name)}(?:=(.*))?$")
    found = []
    for line in text.splitlines():
        match = pattern.match(line.strip())
        if match:
            found.append(match.group(1) or "")
    return found


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


def test_the_validator_defaults_to_the_operator_built_public_backend_image():
    text = _dockerfile()
    assert PRIVATE_BASE not in text
    assert "phase11" not in text.lower()
    assert _declarations(text, "VALIDATOR_BASE")[0] == PUBLIC_BASE
    # Only the public tag is defaulted; nothing else overrides the base.
    assert not any(_declarations(text, "VALIDATOR_BASE")[1:])
    assert "FROM ${VALIDATOR_BASE}" in text


def test_the_expected_base_id_is_required_from_the_caller():
    text = _dockerfile()
    assert HOST_SPECIFIC_ID not in text
    # Declared, never defaulted: an implicit ID would be machine-specific.
    assert _declarations(text, "VALIDATOR_BASE_ID") == [""]
    guard = [
        instruction
        for instruction in _instructions(text)
        if instruction.startswith("RUN ") and "VALIDATOR_BASE_ID" in instruction
    ]
    assert len(guard) == 1, guard
    # A missing or malformed value fails the build instead of labelling a tag.
    assert "sha256:[0-9a-f]{64}" in guard[0] and "exit 1" in guard[0]
    assert 'LABEL org.itsm.validator.base.id="${VALIDATOR_BASE_ID}"' in text


def test_the_documented_build_takes_exactly_two_build_args():
    section = _operator_section()
    doc = SDK_DOC.read_text(encoding="utf-8")
    assert PRIVATE_BASE not in doc
    assert HOST_SPECIFIC_ID not in doc
    assert PUBLIC_BASE in section
    assert f"docker image inspect {PUBLIC_BASE} --format '{{{{.Id}}}}'" in section
    assert "VALIDATOR_BASE_ID" in section and "required" in section
    assert BUN_DIGEST in section

    blocks = re.findall(r"```bash\n(.*?)```", section, re.S)
    commands = [block for block in blocks if "Dockerfile.extension-validator" in block]
    assert len(commands) == 1, commands
    command = commands[0]
    assert re.findall(r'--build-arg "?([A-Z_]+)=', command) == [
        "VALIDATOR_BASE_ID",
        "BUN_IMAGE",
    ]
    assert f"--build-arg BUN_IMAGE={BUN_DIGEST}" in command
    assert "--pull=false" in command and "--network=none" in command
    assert "-f Dockerfile.extension-validator -t itsm-extension-validator:1 ." in command
    # The base is the public backend image built from this repository.
    assert f"-t {PUBLIC_BASE} ." in section


def test_the_validator_image_keeps_offline_isolation_and_fixed_runtime():
    text = _dockerfile()
    assert f"ARG BUN_IMAGE={BUN_DIGEST}" in text
    assert "COPY --from=js" in text
    assert "rm -rf /app /data" in text
    assert "COPY --chown=10001:10001 itsm/extensions/sdk /validator/itsm/extensions/sdk" in text
    assert "USER 10001:10001" in text
    assert (
        'CMD ["/usr/local/bin/python3", "-I", "-B", '
        '"/validator/itsm/extensions/sdk/validator/run.py"]'
    ) in text
    assert 'LABEL org.itsm.validator.network="none"' in text
