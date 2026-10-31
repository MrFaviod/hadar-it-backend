"""Manifest-level checks shipped inside the declarative example package."""

import json
import unittest
from pathlib import Path

MANIFEST = json.loads(
    (Path(__file__).resolve().parents[1] / "extension.json").read_text(encoding="utf-8")
)


class DeclarativeManifestTests(unittest.TestCase):
    def test_runtime_is_declarative_and_ships_no_code(self):
        self.assertEqual(MANIFEST["runtime"], "declarative")
        self.assertFalse((Path(__file__).resolve().parents[1] / "backend.py").exists())

    def test_every_operation_targets_a_declared_collection(self):
        collections = {item["name"] for item in MANIFEST["collections"]}
        kinds = set()
        for operation in MANIFEST["operations"]:
            kinds.add(operation["kind"])
            self.assertIn(operation["collection"], collections)
        self.assertEqual(kinds, {"list", "get", "put", "delete"})

    def test_collection_schema_uses_only_the_public_subset(self):
        schema = MANIFEST["collections"][0]["schema"]
        self.assertEqual(schema["type"], "object")
        self.assertTrue(schema["required"])
        for field in schema["properties"].values():
            self.assertIn(field["type"], ("string", "number", "integer", "boolean", "null"))


if __name__ == "__main__":
    unittest.main()
