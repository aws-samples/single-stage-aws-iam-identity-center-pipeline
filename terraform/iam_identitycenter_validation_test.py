import logging
import unittest
from validation.iam_identitycenter_validation import validate_unique_permissionset_name


class TestValidateUniquePermissionSetName(unittest.TestCase):

    def test_unique_permission_set_names(
        self,
    ):
        permission_set_templates = {
            "template1": {"Name": "PermissionSet1"},
            "template2": {"Name": "PermissionSet2"},
            "template3": {"Name": "PermissionSet3"},
        }
        result = validate_unique_permissionset_name(permission_set_templates)
        self.assertTrue(result)

    def test_duplicate_permission_set_names(
        self,
    ):
        permission_set_templates = {
            "template1": {"Name": "PermissionSet1"},
            "template2": {"Name": "PermissionSet2"},
            "template3": {"Name": "PermissionSet1"},
        }
        with self.assertRaises(Exception) as context:
            validate_unique_permissionset_name(permission_set_templates)
        self.assertTrue("Duplicate Permission Set Names" in str(context.exception))


if __name__ == "__main__":
    unittest.main()
