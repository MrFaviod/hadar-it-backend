# Report request shape

`prepare_report`, `generate_report` and `generate_labels` take one `request`
object, not top-level format arguments. The bounded fields are:

- `family`: `inventory`, `history` or `warranty`.
- `templateId` for a saved template, or an explicit `template` definition.
- `assetIds`: explicit asset UUIDs, bounded by the service.
- `filters`: `search`, `category`, `site`, `siteId`, `locationId`,
  `responsiblePersonId`, `status`, `archived`, `from`, `to`, `actor`, `event`,
  `warrantyFilter`.
- `fields`, `group`, `mode` (`consolidated` or `individual`), `output`
  (`pdf`, `csv` or `xlsx`) and `name`.
- `labels` for `generate_labels`, with bounded format/geometry/field options.

Preview first: `prepare_report` returns `matched`, at most twenty preview
rows/assets, columns, summary and `hasMore`. Narrow the request when
`hasMore` is true; do not describe the preview as the full dataset.

`generate_report` queues durable work and returns a job id. Poll
`report_job_status`; `report_documents` returns protected references, never
bytes, server paths or fabricated URLs. Report only the queued job and the
documents the service returns. Sharing outside the caller's scope needs the
separate sharing authority.
