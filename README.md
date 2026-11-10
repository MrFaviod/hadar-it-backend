# Hadar IT · Backend

API, domain services and background jobs for
[Hadar IT](https://github.com/MrFaviod/hadar-it).
REST, the assistant and MCP clients share server-enforced permissions.

Alpha software. Not ready for production. AI and external integrations need
configuration; queued work requires a running worker.

## Development

Python 3.14+, FastAPI, SQLAlchemy, Alembic and Huey.
From this repository:

```bash
python3.14 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt -r requirements-dev.txt
```

Follow the central development guide to initialize disposable storage and start
the API and worker. Installing dependencies does not initialize a database or
create an account. The running API serves OpenAPI at `/docs`.

## Documentation

- [Install Hadar](https://github.com/MrFaviod/hadar-it/blob/master/INSTALL.md)
- [Backend development](https://github.com/MrFaviod/hadar-it/blob/master/docs/backend/development.md)
- [Personal API keys and MCP](https://github.com/MrFaviod/hadar-it/blob/master/docs/backend/personal-api-keys.md)
- [Extension SDK](https://github.com/MrFaviod/hadar-it/blob/master/docs/backend/extensions-sdk.md)

Maintained guides live in the main repository. Local `docs/` and agent instructions
are internal and ignored. Packaged SDK references and agent skills under `itsm/`
remain part of the product.
[Report an issue](https://github.com/MrFaviod/hadar-it-backend/issues).
