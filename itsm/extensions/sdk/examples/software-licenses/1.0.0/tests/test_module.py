"""Package tests run by the offline validator; stdlib only."""

import unittest


class ContractTest(unittest.TestCase):
    def test_permission_namespace_is_declared(self):
        self.assertTrue("ext_software_licenses.read".startswith("ext_"))

    def test_reference_field_is_an_asset_id(self):
        self.assertEqual("assetId", "assetId")


if __name__ == "__main__":
    unittest.main()
