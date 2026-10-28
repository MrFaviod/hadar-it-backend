"""Real operation and migration checks shipped inside the generated package."""

import sys
import unittest
from pathlib import Path

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
if str(PACKAGE_ROOT) not in sys.path:
    sys.path.insert(0, str(PACKAGE_ROOT))

import backend  # noqa: E402


class MemoryStore:
    """Minimal host-store contract used only by this package test."""

    def __init__(self):
        self.records = {}
        self.versions = {}

    def list(self, collection, limit=20, offset=0, filters=None):
        assert collection == "records"
        rows = []
        for record_id in sorted(self.records):
            data = self.records[record_id]
            if filters:
                if any(data.get(key) != value for key, value in filters.items()):
                    continue
            rows.append(
                {
                    "id": record_id,
                    "version": self.versions[record_id],
                    "data": dict(data),
                }
            )
        return {"items": rows[offset : offset + limit], "total": len(rows)}

    def get(self, collection, record_id):
        assert collection == "records"
        if record_id not in self.records:
            return None
        return {
            "id": record_id,
            "version": self.versions[record_id],
            "data": dict(self.records[record_id]),
        }

    def put(self, collection, record_id, data, expected_version=None):
        assert collection == "records"
        assert isinstance(data, dict)
        if expected_version == 0 and record_id in self.records:
            raise RuntimeError("record already exists")
        if expected_version not in (None, 0):
            if self.versions.get(record_id) != expected_version:
                raise RuntimeError("record version conflict")
        self.records[record_id] = dict(data)
        self.versions[record_id] = self.versions.get(record_id, 0) + 1
        return self.get(collection, record_id)

    def delete(self, collection, record_id):
        self.records.pop(record_id, None)
        self.versions.pop(record_id, None)
        return True


class Context:
    def __init__(self):
        self.store = MemoryStore()
        self.allowed = {
            backend.READ_PERMISSION,
            backend.WRITE_PERMISSION,
        }

    def authorize(self, permission):
        if permission not in self.allowed:
            raise PermissionError(permission)



class SDK:
    def __init__(self):
        self.operations = {}
        self.migrations = {}

    def operation(self, name, handler):
        self.operations[name] = handler

    def migration(self, name, handler):
        self.migrations[name] = handler

    def schedule(self, name, handler):
        raise AssertionError("this example declares no schedules")


class BackendTests(unittest.TestCase):
    def setUp(self):
        self.sdk = SDK()
        backend.register(self.sdk)
        self.context = Context()

    def test_register_binds_the_declared_handlers(self):
        self.assertEqual(set(self.sdk.operations), {"list_records", "create_record"})
        self.assertEqual(set(self.sdk.migrations), {"normalize_status"})

    def test_create_then_list_round_trip(self):
        created = backend.create_record(
            self.context, title="Router principal", notes="Armario B"
        )
        record = created["record"]
        self.assertEqual(record["title"], "Router principal")
        self.assertEqual(record["status"], "open")
        self.assertTrue(record["id"])

        listed = backend.list_records(self.context, limit=10)
        self.assertEqual(listed["total"], 1)
        self.assertEqual(listed["items"][0]["id"], record["id"])
        self.assertEqual(listed["items"][0]["notes"], "Armario B")

    def test_asset_filter_keeps_records_scoped_without_mutating_assets(self):
        first = backend.create_record(self.context, title="Router", asset_id="asset-one")
        backend.create_record(self.context, title="Switch", asset_id="asset-two")
        backend.create_record(self.context, title="Sin vínculo")
        listed = backend.list_records(self.context, asset_id="asset-one", limit=1)
        self.assertEqual(listed["total"], 1)
        self.assertEqual(listed["items"][0]["id"], first["record"]["id"])
        self.assertEqual(listed["items"][0]["assetId"], "asset-one")
        self.assertEqual(backend.list_records(self.context)["total"], 3)
        with self.assertRaises(ValueError):
            backend.create_record(self.context, title="Inválido", asset_id="")
        self.assertEqual(backend.list_records(self.context)["total"], 3)

    def test_migration_normalizes_legacy_records(self):
        self.context.store.put(
            "records",
            "legacy-1",
            {"title": "Legacy", "notes": ""},
            expected_version=0,
        )
        result = backend.normalize_status(self.context)
        self.assertEqual(result["migrated"], 1)
        stored = self.context.store.get("records", "legacy-1")
        self.assertEqual(stored["data"]["status"], "open")

    def test_migration_normalizes_records_beyond_one_store_page(self):
        for index in range(201):
            self.context.store.put(
                "records", "legacy-%03d" % index,
                {"title": "Legacy %d" % index, "notes": ""}, expected_version=0,
            )
        result = backend.normalize_status(self.context)
        self.assertEqual(result, {"migrated": 201})
        for index in range(201):
            stored = self.context.store.get("records", "legacy-%03d" % index)
            self.assertEqual(stored["data"]["status"], "open")
            self.assertEqual(stored["version"], 2)
        self.assertEqual(backend.normalize_status(self.context), {"migrated": 0})

    def test_list_rejects_out_of_range_limit(self):
        with self.assertRaises(ValueError):
            backend.list_records(self.context, limit=0)


if __name__ == "__main__":
    unittest.main()
