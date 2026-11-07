# Validation

`extension_workspace_validate` builds deterministic ZIP bytes from the
workspace, computes their SHA-256 digest, and sends only those bytes plus a
bounded protocol header to the fixed validator container over stdin.

## Fixed runner

The wrapper executes a server-owned command with:

- `--network none`, `--read-only`, `--cap-drop ALL`,
  `--security-opt no-new-privileges`, `--user 10001:10001`;
- bounded `--pids-limit`, `--memory`, `--cpus` and `/tmp` tmpfs;
- no volume, bind mount, Docker socket, `--privileged` or environment file;
- a unique container name, `--rm`, and a fixed image reference;
- no candidate argv, path, shell, package manager or online install.

The image is fixed by the operator. It contains the SDK validator harness and
a JavaScript engine, but no host application checkout. The archive is the only
candidate input.

## Checks

| Check | Evidence |
| --- | --- |
| `protocol` | The bounded frame and declared digest are intact. |
| `archive` | ZIP containment, encryption, links, duplicates and limits. |
| `manifest` | Canonical JSON Schema plus semantic cross-field rules. |
| `layout` | Required root files, declared skills and `tests/*.py`. |
| `backend` | `backend.py` imports only stdlib and declares `register(sdk)`. |
| `execution` | The bounded candidate subprocess exited normally and returned only the expected per-check diagnostics. |
| `registration` | Every declared operation, migration and schedule is bound. |
| `operations` | Each operation runs once with schema-derived arguments and returns bounded JSON. |
| `migrations` | Each migration handler runs and returns bounded JSON. |
| `schedules` | Each schedule handler runs, or none are declared. |
| `tests` | The package's own `unittest` suite passes (not merely imports). |
| `frontend` | JavaScript syntax and the actual `register(id, {components})` call. |

A compile-only result is not business validation. The generated example ships
real operation and migration tests.

The fixed parent owns archive framing, digest, static checks and final report
status. Candidate Python runs in a separate bounded subprocess with closed
unrelated file descriptors. Candidate stdout/stderr are logs, never a report;
premature exit, missing completion evidence or a candidate top-level report
fails validation. Only exact, bounded, normally completed check diagnostics are
merged. Those diagnostics and package tests are **not security attestations**:
same-UID subprocesses are not a hostile-code sandbox. The offline container is
the security boundary protecting the application, and exact-digest human
trusted-native approval remains mandatory.

## Report

The trusted report has exactly seven fields:

```json
{
  "status": "passed",
  "digest": "<sha256 of the exact package bytes>",
  "sdkVersion": 1,
  "checks": [{"name": "...", "status": "passed", "detail": "..."}],
  "errors": [],
  "container": {"image": "...", "network": "none", "engine": "python ...; js node ...", "...": "..."},
  "completedAt": "2026-10-28T10:00:00+00:00"
}
```

The host rejects unknown fields, mismatched digests, missing/invalid
completion times and a `passed` report containing failed checks or errors.
Engine versions, limits and protocol metadata live inside `container` or a
check detail, never as competing top-level fields. A validation report is
never accepted from a user request. The host records it only through the
trusted internal recorder bound to the candidate revision.

Successful check details contain bounded counts, file paths and handler names,
never a source-file dictionary or a temporary module representation. The
context fixture uses immutable principal attributes, canonical store envelopes
and versions, nested rollback, empty read-only asset search pages and the exact
keyword-only notice signature. It does not prove production asset/recipient
authorization or queue delivery; those remain host integration checks.
