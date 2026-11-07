# Maintenance plan filters and completion

`search_maintenance` supports `state`, `status`, `category`, `site`,
`site_id`, `asset_id`, `maintenance_type`, `due_from`, `due_to`,
`completed_from`, `completed_to`, `upcoming_days`, `limit` and `offset`.
Choose the narrowest filter the user actually stated; report the returned
window and pagination instead of assuming the full schedule.

`complete_maintenance` needs the real `plan_id`, `completed_on` and factual
notes. The service records one completion and calculates the next due date;
never calculate or announce that date yourself. A plan may cover several
assets, so one completion does not prove work on an unlisted asset.

Creating, editing or rescheduling plans and templates is not exposed here.
Direct those changes to the authorized maintenance screens and do not report
them as applied. If the user supplies only a plan description, search first and
ask for the real plan id rather than inventing one.
