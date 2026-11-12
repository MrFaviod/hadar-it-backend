# Hadar IT · Backend

The API, domain services and background worker of [Hadar IT](https://github.com/MrFaviod/hadar-it). The browser, the built-in assistant (Pydantic AI) and MCP clients (FastMCP) all call the same domain services, and identity and permissions are enforced here, on the server.

> **Alpha.** Not ready for production. To run the whole application, follow the [installation guide](https://github.com/MrFaviod/hadar-it/blob/master/INSTALL.md). AI and external integrations need their own configuration, and queued work needs a running worker.

## Develop

Python 3.14 or later, FastAPI, SQLAlchemy, Alembic and Huey. From this repository:

```bash
python3.14 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt -r requirements-dev.txt
```

Installing dependencies does not create a database or an account. The [backend development guide](https://github.com/MrFaviod/hadar-it/blob/master/docs/backend/development.md) walks through a disposable local workspace: initialize storage, start the API on port 8000 and run the worker. The running API serves its OpenAPI reference at `/docs`.

## Check

```bash
.venv/bin/python -m pytest
.venv/bin/python -m ruff check itsm tests migrations
```

Never point tests or migrations at a database you want to keep.

## Documentation

Maintained guides live in the main repository:

- [Backend development](https://github.com/MrFaviod/hadar-it/blob/master/docs/backend/development.md)
- [Personal API keys and MCP](https://github.com/MrFaviod/hadar-it/blob/master/docs/backend/personal-api-keys.md)
- [Extension SDK](https://github.com/MrFaviod/hadar-it/blob/master/docs/backend/extensions-sdk.md)
- [All documentation](https://github.com/MrFaviod/hadar-it/blob/master/docs/README.md)

Local `docs/` and agent instructions in this repository are internal working files and are not published. The SDK references and agent skills packaged under `itsm/` are part of the product.

[Report an issue](https://github.com/MrFaviod/hadar-it-backend/issues)
