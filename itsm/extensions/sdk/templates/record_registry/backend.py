"""Record registry example: sandboxed operations, collections and migration.

The host never imports this module. Every invocation starts a fresh
``python -E -s -S -B`` runner in the module data directory, restricted by
rlimits, ``no_new_privs``, Landlock and a seccomp deny-list, and calls
``register(sdk)`` there. Core data is reachable only through authorized host
capabilities; persistence is this module's own SQLite file.
"""

import uuid

READ_PERMISSION = "{{PERMISSION_PREFIX}}records_read"
WRITE_PERMISSION = "{{PERMISSION_PREFIX}}records_write"
COLLECTION = "records"
MAX_LIST = 100
DEFAULT_LIST = 20


def _row(row):
    """Flatten the host store record envelope into a JSON result."""
    result = dict(row["data"])
    result["id"] = row["id"]
    result["version"] = row["version"]
    return result


def _text(value, field, maximum):
    if not isinstance(value, str):
        raise ValueError(f"{field} must be text")
    cleaned = value.strip()
    if not cleaned:
        raise ValueError(f"{field} is required")
    if len(cleaned) > maximum:
        raise ValueError(f"{field} must be at most {maximum} characters")
    return cleaned


def list_records(context, limit=DEFAULT_LIST, status=None, asset_id=None):
    """Return the module-scoped records visible to the caller."""
    context.authorize(READ_PERMISSION)
    if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1 or limit > MAX_LIST:
        raise ValueError(f"limit must be an integer between 1 and {MAX_LIST}")
    if status is not None and status not in ("open", "closed"):
        raise ValueError("status must be open or closed")
    filters = {}
    if status:
        filters["status"] = status
    if asset_id is not None:
        filters["assetId"] = _text(asset_id, "asset_id", 64)
    page = context.store.list(COLLECTION, limit=limit, offset=0, filters=filters)
    return {"items": [_row(row) for row in page["items"]], "total": page["total"]}


def create_record(context, title, status="open", notes="", asset_id=None):
    """Create a record with a server-generated identifier."""
    context.authorize(WRITE_PERMISSION)
    clean_title = _text(title, "title", 200)
    if status not in ("open", "closed"):
        raise ValueError("status must be open or closed")
    clean_notes = "" if notes is None else _text(notes, "notes", 2000) if notes else ""
    record = {
        "title": clean_title,
        "status": status,
        "notes": clean_notes,
    }
    if asset_id is not None:
        record["assetId"] = _text(asset_id, "asset_id", 64)
    record_id = uuid.uuid4().hex
    stored = context.store.put(COLLECTION, record_id, record, expected_version=0)
    return {"record": _row(stored)}


def normalize_status(context):
    """Schema migration 1 -> 2: legacy records without status become open."""
    offset = 0
    migrated = 0
    while True:
        page = context.store.list(COLLECTION, limit=200, offset=offset)
        for row in page["items"]:
            data = row["data"]
            if data.get("status"):
                continue
            updated = dict(data)
            updated["status"] = "open"
            context.store.put(COLLECTION, row["id"], updated, expected_version=row["version"])
            migrated += 1
        offset += len(page["items"])
        if offset >= page["total"]:
            break
    return {"migrated": migrated}


def register(sdk):
    """Bind every manifest operation and migration to a real callable."""
    sdk.operation("list_records", list_records)
    sdk.operation("create_record", create_record)
    sdk.migration("normalize_status", normalize_status)
