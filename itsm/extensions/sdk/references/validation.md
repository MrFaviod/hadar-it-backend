# Validation

`extension_workspace_validate` builds deterministic ZIP bytes from the
workspace, computes their SHA-256 digest, and sends only those bytes plus a
bounded protocol header to the fixed validator container over stdin. The
protocol version is 2, matching `sdkVersion: 2`.

## Fixed runner

The wrapper executes a server-owned command with:

- `--network none`, `--read-only`, `--cap-drop ALL`,
  `--security-opt no-new-privileges`, `--user 10001:10001`;
- bounded `--pids-limit`, `--memory`, `--cpus` and `/tmp` tmpfs;
- no volume, bind mount, Docker socket, `--privileged` or environment file;
- a unique container name, `--rm`, and a fixed image reference;
- no candidate argv, path, shell, package manager or online install.

The image is fixed by the operator. It contains the SDK validator harness and a
JavaScript engine, but no host application checkout. The archive is the only
candidate input. The same harness can run offline through
`itsm.extensions.sdk.validator.harness.validate_payload`, which the test suite
uses for evidence without Docker.

## Checks

| Check | Evidence |
| --- | --- |
| `protocol` | The bounded frame and declared digest are intact. |
| `archive` | ZIP containment, encryption, links, duplicates and limits. |
| `manifest` | Canonical JSON Schema plus semantic cross-field rules, including runtime, capabilities, collection schemas and declarative kinds. |
| `layout` | Required root files for the declared runtime, declared skills and `tests/*.py`. |
| `backend` | Sandboxed: `backend.py` imports only stdlib, has no blocked calls and declares `register(sdk)`. Declarative: reported as code-less. |
| `execution` | Sandboxed only: the bounded candidate subprocess exited normally and returned only the expected per-check diagnostics. |
| `registration` | Sandboxed: every declared operation, migration, schedule, subscription and reconcile handler is bound. Declarative: reported as having no handlers. |
| `operations` | Sandboxed: every handler accepts the context and both required-only and all declared keyword arguments. Declarative: each declared kind, its arguments and its collection are checked against the schema. |
| `migrations` | Sandboxed: each migration handler runs and returns bounded JSON. Declarative: must declare none. |
| `schedules` | Sandboxed: each schedule handler runs, or none are declared. Declarative: must declare none. |
| `tests` | The package's own `unittest` suite passes (not merely imports). |
| `frontend` | Declarative views reference declared operations; an isolated bundle must parse and call `window.ITSMExtension.register(...)`. |

Each check name appears exactly once in the report, for both runtimes.

A signature result is not business validation. The required package `unittest`
suite must execute operations with explicit domain fixtures, including existing
and missing assets, valid and invalid dates, authorization and optimistic-version
errors where applicable. The generated examples ship real operation and migration
tests. The fixed validator cannot invent valid inventory IDs or other business
preconditions, and never catches an operation error to turn it into a pass.

The fixed parent owns archive framing, digest, static checks and final report
status. Candidate Python runs in a separate bounded subprocess with closed
unrelated file descriptors. Candidate stdout/stderr are logs, never a report;
exit without valid completion evidence or a candidate top-level report fails
validation. Only exact, bounded check diagnostics are merged. Candidate code can
forge its own execution evidence; only parent framing and static checks are
independent. Diagnostics and package tests are **not security attestations**:
same-UID subprocesses are not a hostile-code sandbox. The offline container
protects the application, and exact-digest human approval remains mandatory.

## Static rules

The backend check rejects imports of `itsm`, `sqlalchemy`, `socket`,
`subprocess`, `ctypes` and `multiprocessing`, relative imports, and
`os.system`/`os.popen`/`os.exec*`/`os.spawn*`/`os.fork`/`ctypes.CDLL` calls with
a message of the form:

```text
contract_gap_required: backend.py uses socket, which needs the network capability.
The SDK v2 runner does not grant it; declare the capability if it is public, or
record a contract gap instead of bypassing isolation.
```

The message names the missing public capability so the fix is a contract
decision, never a private-structure workaround. SQL DDL against core objects is
impossible by construction: the runner can open only its own module file and
Landlock denies every other path.

## Report

The trusted report has exactly seven fields:

```json
{
  "status": "passed",
  "digest": "<sha256 of the exact package bytes>",
  "sdkVersion": 2,
  "checks": [{"name": "...", "status": "passed", "detail": "..."}],
  "errors": [],
  "container": {"image": "...", "network": "none", "engine": "python ...; js bun ...", "...": "..."},
  "completedAt": "2026-10-28T10:00:00+00:00"
}
```

The host rejects unknown fields, mismatched digests, a `sdkVersion` other than 2,
missing/invalid completion times and a `passed` report containing failed checks
or errors. A validation report is never accepted from a user request. The host
records it only through the trusted internal recorder bound to the candidate
revision.

The harness fakes mirror the runtime: `context.principal` is a dict, store
envelopes and versions match the host, notices use the keyword-only signature
including `idempotency_key`, and asset reads use an empty read-only fixture. It
does not prove production asset/recipient authorization or queue delivery; those
remain host integration checks.
