"""Serve the database-free setup application with uvicorn on port 8100."""

from __future__ import annotations

import uvicorn

from itsm.setup.api import create_setup_app

SETUP_HOST = "0.0.0.0"
SETUP_PORT = 8100


def main() -> None:
    uvicorn.run(create_setup_app(), host=SETUP_HOST, port=SETUP_PORT)


if __name__ == "__main__":
    main()
