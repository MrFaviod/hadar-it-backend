# Extension SDK quickstart

The SDK turns a bounded ZIP package into a native extension: a Python backend,
a Vue frontend registered against the host, namespaced collections, ordered
schema migrations, schedules and skills. Approved code runs inside the host
process. It is trusted native code, not a sandbox and not hostile-code
isolation.

## 1. Generate the working example

```bash
python -m itsm.extensions generate ./my-records \
  --id my-records \
  --name "Mis registros" \
  --description "Registros internos del equipo."
cd ./my-records
```

`generate` creates `extension.json`, `backend.py`, `frontend.js`,
`skills/my-records/SKILL.md` and `tests/test_backend.py`. The example is a
neutral record registry: it has two operations, one collection and one real
schema migration. It contains no license or product-specific behavior.

The native asset panel receives the host's read-only `asset` and calls
`list_records({asset_id: asset.id, limit: 1})`. Create a linked module record
with `create_record({title: "Revisión", asset_id: "<existing asset id>"})`.
The optional link filters module-owned records; it never writes core assets.
Calls without `asset_id` retain the ordinary registry behavior.

## 2. Read the contract before editing

- `schema/extension.schema.json` is the machine-readable manifest contract.
- `references/manifest.md` explains every field.
- `references/backend.md` documents `register(sdk)` and `handler(context, **kwargs)`.
- `references/frontend.md` documents `window.ITSMExtensions.register`.
- `references/collections.md`, `references/migrations.md` and
  `references/security.md` cover durable data and the trust boundary.

Use `extension_sdk_index` and `extension_sdk_reference` through the shared
agent tool dispatcher, or read the packaged files directly.

## 3. Pack and inspect

```bash
python -m itsm.extensions pack ./my-records --output ./my-records.zip
python -m itsm.extensions inspect ./my-records.zip
python -m itsm.extensions validate ./my-records.zip --image itsm-extension-validator:1
```

`validate` sends only the bounded archive and a small protocol header to a
fixed offline container. It does not copy the host checkout or accept a
shell command. The image must be built by the operator; see
`docs/extensions-sdk.md`.

## 4. Develop through a bounded workspace

The agent tools expose workspaces owned by the authenticated actor:

1. `extension_workspace_create` seeds the working example.
2. `extension_workspace_files`, `extension_workspace_read` and
   `extension_workspace_write` browse and edit only supported package paths.
3. `extension_workspace_validate` builds the actual package bytes and runs the
   fixed validator.
4. `extension_workspace_submit` creates a pending candidate. It never approves
   or installs; a human Superadmin reviews the exact digest in the UI.
5. `extension_workspace_create` is not an install action. There is no chat
   approval path.

Any source edit invalidates the current validation. Denied operations leave
the workspace and its validation unchanged.

## 5. Install is a separate human action

The candidate detail shows the manifest, digest, validation, permission delta,
migration plan and rollback compatibility. Installation requires a human
Superadmin decision bound to the exact digest and the expected installed
revision. Agents can submit and inspect; they cannot approve.
