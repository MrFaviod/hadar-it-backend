"""Fixed container entrypoint. Reads one bounded frame from stdin, writes JSON."""

from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
for base in (HERE, *HERE.parents[:4]):
    text = str(base)
    if text not in sys.path:
        sys.path.insert(0, text)

from itsm.extensions.sdk.validator.harness import execution_main, main  # noqa: E402

if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "--exercise":
        raise SystemExit(execution_main(Path(sys.argv[2]), int(sys.argv[3])))
    if len(sys.argv) != 1:
        raise SystemExit("invalid fixed validator arguments")
    raise SystemExit(main())
