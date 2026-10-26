---
name: itsm-reporting
description: "Trigger: report template, preview, export job or physical labels. Prepare and track ITSM reports through authorized tools."
license: UNLICENSED
metadata:
  author: "ITSM project"
  version: "1.0.0"
tools:
  - list_report_templates
  - prepare_report
  - generate_report
  - report_job_status
  - report_documents
  - generate_labels
permissions:
  - assets.view
capabilities:
  - reports.read
  - reports.generate
---
# ITSM reporting

## Activation Contract
Load when the user asks which report templates exist, wants a preview of report data, needs a PDF, CSV or Excel export, wants job progress, or needs asset labels.

## Hard Rules
- Start with `list_report_templates`; never invent a template id, column set or label option.
- `prepare_report` is the preview and returns at most twenty rows; `hasMore: true` means narrow the request instead of claiming the full result.
- `generate_report` queues durable work; report the job id and current status, never a finished state that the service did not return.
- `report_documents` returns protected references, not file bytes or server paths. Never construct a download path.
- `generate_labels` requires explicit label options; ask before queueing physical output.
- A report shared outside the caller's own scope needs the separate sharing authority and is not part of these tools.

## Decision Gates
| Need | Call |
| --- | --- |
| Available templates | `list_report_templates` |
| Inspect data first | `prepare_report` |
| Queue an export | `generate_report` |
| Check progress | `report_job_status` |
| Retrieve protected references | `report_documents` |
| Print labels | `generate_labels` with `labels` options |

## Execution Steps
1. List templates and confirm the requested scope, format and columns.
2. Preview the request and report `matched`, `hasMore` and a bounded row sample.
3. Queue generation only after the preview matches the user's intent.
4. Poll `report_job_status` while the job is pending; then call `report_documents`.
5. Report job id, status, formats and document references.

## Output Contract
Return template id, scope, matched count, preview rows, job id, status and protected document references. Relay `permission denied` verbatim; never claim a document exists before the job reports it.

## Example
`prepare_report` with a `request` selecting a template and site returns `matched: 42` and `hasMore: true`. Narrow the `request` filters, preview again, then `generate_report` with the same `request` plus `output: "pdf"`. Poll `report_job_status` with the returned `job_id` and return the protected documents.

## References
- [Report request shape](references/request-shape.md)
