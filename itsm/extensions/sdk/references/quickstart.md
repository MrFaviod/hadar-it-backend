# Extension SDK v2 quickstart

The SDK turns a bounded ZIP package into an isolated extension. A **sandboxed**
module ships Python that always runs in a restricted runner process; a
**declarative** module ships no code at all and the host executes its declared
`list`/`get`/`put`/`delete` operations. Both keep business data in their own
SQLite file, never in the core database.

## 1. Generate a working example

```bash
python -m itsm.extensions generate ./my-records \
  --id my-records \
  --name "Mis registros" \
  --description "Registros internos del equipo." \
  --runtime sandboxed

python -m itsm.extensions generate ./my-notes \
  --id my-notes \
  --name "Mis notas" \
  --description "Notas declarativas del equipo." \
  --runtime declarative
```

`--runtime sandboxed` (the default) writes `extension.json`, `backend.py`,
`skills/<id>/SKILL.md` and `tests/test_backend.py`. `--runtime declarative`
writes `extension.json`, `skills/<id>/SKILL.md` and `tests/test_module.py`, and
no `backend.py`.

Neither example ships `frontend.js`: pages and asset panels are declarative
`view.table`/`view.form` descriptions rendered by the host. A module bundle is
only allowed for an isolated iframe component declared as
`{"isolated": {"component": "..."}}` with `frontend.entry: "frontend.js"`.

## 2. Read the contract before editing

- `schema/extension.schema.json` is the machine-readable manifest contract.
- `references/manifest.md` explains every field, runtime and capability.
- `references/backend.md` documents `register(sdk)` and `handler(context, **kwargs)`.
- `references/frontend.md` documents declarative views and the isolated bridge.
- `references/collections.md`, `references/migrations.md` and
  `references/security.md` cover durable data, snapshots and the isolation model.

Use `extension_sdk_index` and `extension_sdk_reference` through the shared agent
tool dispatcher, or read the packaged files directly.

## 3. Pack and inspect

```bash
python -m itsm.extensions pack ./my-records --output ./my-records.zip
python -m itsm.extensions inspect ./my-records.zip
python -m itsm.extensions validate ./my-records.zip --image itsm-extension-validator:1
```

`validate` sends only the bounded archive and a small protocol header to a fixed
offline container. It does not copy the host checkout or accept a shell command.
The image must be built by the operator; see `docs/extensions-sdk.md`.

## 4. Develop through a bounded workspace

The agent tools expose workspaces owned by the authenticated actor:

1. `extension_workspace_create` seeds the working example.
2. `extension_workspace_files`, `extension_workspace_read` and
   `extension_workspace_write` browse and edit only supported package paths.
3. `extension_workspace_validate` builds the actual package bytes and runs the
   fixed validator.
4. `extension_workspace_submit` creates a pending candidate. It never approves
   or installs; a human Superadmin reviews the exact digest in the UI.

Any source edit invalidates the current validation. Denied operations leave the
workspace and its validation unchanged.

## 5. Install is a separate human action

The candidate detail shows the manifest, digest, runtime, validation, permission
delta, migration plan and rollback compatibility. Installation requires a human
Superadmin decision bound to the exact digest and the expected installed
revision. Agents can submit and inspect; they cannot approve, enable, disable,
roll back or uninstall.
