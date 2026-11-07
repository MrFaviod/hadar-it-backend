# Read semantics and truncation

These four tools are read-only and caller-scoped:

- `get_operational_summary(period, category, site_id)` returns the bounded
  operational overview for that window. State the period used.
- `search_everything(query, kinds, limit, offset)` accepts only known result
  kinds and a bounded page. Report `total`, `limit`, `offset`, `truncated`,
  `engine` and `fallback` exactly as returned.
- `query_relationships(asset_id, depth, direction, type_key, limit, offset)`
  traverses the persisted graph or pages it globally. Its `truncated`,
  `nodesTruncated`, `edgesTruncated` and `depthTruncated` flags are part of the
  answer; never hide them.
- `list_saved_views()` returns only the caller's views, favorites, shortcuts
  and theme; it cannot read another identity's workspace.

A truncated page is not proof that no further records exist. Fetch the next
bounded page when needed, or ask the user to narrow the query. Deployment
maintenance and host-level operations are outside these tools; never simulate
them through search, summary or graph calls. For mutations, hand off to the
domain skill that owns the record.
