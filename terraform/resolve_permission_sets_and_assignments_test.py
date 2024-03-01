# Unit Tests for resolve_permission_sets_and_assignments.py

# Required mocks
# sso-admin: list_instances
# sso-admin: describe_permission_set
# sso-admin: list_permission_sets
# organizations: describe_organization
# organizations: list_accounts_for_parent
# organizations: list_accounts
# organizations: list_roots
# organizations: list_organizational_units_for_parent
# identitystore: list_users
# identitystore: list_groups

# Create a mock for the boto3 client
import datetime
import json
import logging
import unittest
from unittest.mock import patch, MagicMock
from botocore.exceptions import ClientError
import resolve_permission_sets_and_assignments

#############
# Main Code #
#############

CLIENT_FACTORY = MagicMock()

# mock Organizations API calls
ORG_MOCK = MagicMock()
# mock identity Store API calls
ID_STORE_MOCK = MagicMock()
# mock SSO client for permission set and assignment APIs
SSO_MOCK = MagicMock()
# mock STS client for getting account ID
STS_MOCK = MagicMock()


def mock_get_client(client_name, *args, **kwargs):
    if client_name == "organizations":
        return ORG_MOCK
    if client_name == "identitystore":
        return ID_STORE_MOCK
    if client_name == "sso-admin":
        return SSO_MOCK
    if client_name == "sts":
        return STS_MOCK
    raise Exception("Attempting to create an unknown client")


class TestHelperFunctions(unittest.TestCase):
    # Mock data for test_get_permission_set_managed_policies()
    test_data = {
        "Name": "test",
        "ManagedPolicies": [
            "arn:aws:iam:::policy/AdministratorAccess",
        ],
    }
    expected_response_string_1 = """
resource "aws_ssoadmin_managed_policy_attachment" "test_managed_policy_AdministratorAccess" {
  lifecycle {
    ignore_changes = [
      instance_arn
    ]
  }
  instance_arn       = local.sso_instance_arn
  managed_policy_arn = "arn:aws:iam:::policy/AdministratorAccess"
  permission_set_arn = aws_ssoadmin_permission_set.test.arn
}
"""
    expected_response_list = [expected_response_string_1]

    def test_get_permission_set_managed_policies(self):
        response = (
            resolve_permission_sets_and_assignments.get_permission_set_managed_policies(
                data=self.test_data,
            )
        )
        print(response)
        print(self.expected_response_list)
        self.assertEqual(response, self.expected_response_list)

    # Mock data for resolve_ou_names()


if __name__ == "__main__":
    unittest.main()
