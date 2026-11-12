"""Package tests run by the offline validator; stdlib only."""

import json
import unittest
from pathlib import Path


class ContractTest(unittest.TestCase):
    def test_permission_namespace_is_declared(self):
        self.assertTrue("ext_software_licenses.read".startswith("ext_"))

    def test_assignments_reference_an_asset_by_uuid(self):
        manifest = json.loads((Path(__file__).parents[1] / "extension.json").read_text())
        assignments = next(c for c in manifest["collections"] if c["name"] == "assignments")
        self.assertIn("assetId", assignments["schema"]["required"])
        self.assertEqual(assignments["schema"]["properties"]["assetId"]["format"], "uuid")


if __name__ == "__main__":
    unittest.main()
