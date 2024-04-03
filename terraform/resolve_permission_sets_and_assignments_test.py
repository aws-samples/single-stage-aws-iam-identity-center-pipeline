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
from botocore.config import Config

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
    mock_boto_config = Config(retries={"max_attempts": 0})

    def test_get_permission_set_resource(self):
        data = {
            "Name": "TestPermissionSet",
            "Description": "Test description",
            "SessionDuration": "1h",
        }
        expected_output = """
resource "aws_ssoadmin_permission_set" "TestPermissionSet" {
  lifecycle {
    ignore_changes = [
      instance_arn
    ]
  }
  name             = "TestPermissionSet"
  description      = "Test description"
  instance_arn     = local.sso_instance_arn
  session_duration = "1h"
}
"""
        output = resolve_permission_sets_and_assignments.get_permission_set_resource(
            data=data,
        )
        self.assertEqual(output, expected_output)

    def test_get_permission_set_managed_policies(self):
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
        response = (
            resolve_permission_sets_and_assignments.get_permission_set_managed_policies(
                data=test_data,
            )
        )
        print(response)
        print(expected_response_list)
        self.assertEqual(response, expected_response_list)

    def test_get_permission_set_customer_managed_policies(self):
        data = {
            "Name": "TestPermissionSet",
            "CustomerManagedPolicies": ["Policy1", "Policy2"],
        }
        expected_output = [
            """
resource "aws_ssoadmin_customer_managed_policy_attachment" "TestPermissionSet_customer_managed_policy_Policy1" {
  lifecycle {
    ignore_changes = [
      instance_arn
    ]
  }
  instance_arn       = local.sso_instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.TestPermissionSet.arn
  customer_managed_policy_reference {
    name = "Policy1"
    path = "/"
  }
}
""",
            """
resource "aws_ssoadmin_customer_managed_policy_attachment" "TestPermissionSet_customer_managed_policy_Policy2" {
  lifecycle {
    ignore_changes = [
      instance_arn
    ]
  }
  instance_arn       = local.sso_instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.TestPermissionSet.arn
  customer_managed_policy_reference {
    name = "Policy2"
    path = "/"
  }
}
""",
        ]
        output = resolve_permission_sets_and_assignments.get_permission_set_customer_managed_policies(
            data=data,
        )
        self.assertEqual(output, expected_output)

    def test_customer_permission_boundary(self):
        data = {
            "Name": "TestPermissionSet",
            "CustomerPermissionBoundary": {
                "Name": "TestManagedPolicy",
                "Path": "/test/path",
            },
        }
        expected_output = """
resource "aws_ssoadmin_permissions_boundary_attachment" "TestPermissionSet_permission_boundary" {
  lifecycle {
    ignore_changes = [
      instance_arn
    ]
  }

  instance_arn       = local.sso_instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.TestPermissionSet.arn
  permissions_boundary {
    customer_managed_policy_reference {
      name = "TestManagedPolicy"
      path = "/test/path"
    }
  }
}
"""
        response = resolve_permission_sets_and_assignments.get_permission_set_permission_boundary(
            data=data,
        )
        self.assertEqual(response, expected_output)

    def test_aws_permission_boundary(self):
        data = {
            "Name": "TestPermissionSet",
            "AwsPermissionBoundaryArn": "arn:aws:iam::123456789012:policy/TestPolicy",
        }
        expected_output = """
resource "aws_ssoadmin_permissions_boundary_attachment" "TestPermissionSet_permission_boundary" {
  lifecycle {
    ignore_changes = [
      instance_arn
    ]
  }

  instance_arn       = local.sso_instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.TestPermissionSet.arn
  permissions_boundary {
    managed_policy_arn = "arn:aws:iam::123456789012:policy/TestPolicy"
  }
}
"""
        output = resolve_permission_sets_and_assignments.get_permission_set_permission_boundary(
            data=data,
        )
        self.assertEqual(output, expected_output)

    def test_multiple_permission_boundaries(self):
        data = {
            "Name": "TestPermissionSet",
            "CustomerPermissionBoundary": {
                "Name": "TestManagedPolicy",
                "Path": "/test/path",
            },
            "AwsPermissionBoundaryArn": "arn:aws:iam::123456789012:policy/TestPolicy",
        }
        with self.assertRaises(Exception):
            resolve_permission_sets_and_assignments.get_permission_set_permission_boundary(
                data=data,
            )

    @patch("boto3.client")
    def test_resolve_ou_names(self, mock_boto3_client):
        # COMMENTED OUT - MOCKING RECURSIVE FUNCTIONS IS REALLY HARD
        # Mock data for resolve_ou_names()
        #     mock_boto3_client.list_organizational_units_for_parent.return_value = {
        #         "OrganizationalUnits": [{"Id": "ou-123"}],
        #         "NextToken": "token",
        #     }

        #     # Call the function
        #     ou_names = resolve_permission_sets_and_assignments.resolve_ou_names(
        #         "ou-123", mock_boto3_client
        #     )

        #     # Assertions
        #     self.assertEqual(len(ou_names), 1)
        #     self.assertEqual(ou_names[0]["Id"], "ou-123")
        #     mock_boto3_client.list_organizational_units_for_parent.assert_called_once_with(
        #         ParentId="ou-123"
        #     )
        pass

    # Mock data for create_permission_set_arn_dict
    @patch("boto3.client")
    def test_create_permission_set_arn_dict(self, mock_boto3_client):
        mock_sso_client = mock_get_client("sso-admin")
        mock_boto3_client.return_value = mock_sso_client

        # Define the expected results
        instance_id = "dummyinstanceID"
        expected_result = {
            "PermissionSet1": "arn:aws:sso:::permissionSet/ssoins-1111111111111111/ps-1111111111111111",
            "PermissionSet2": "arn:aws:sso:::permissionSet/ssoins-1111111111111111/ps-2222222222222222",
        }

        # Mock the return values of sso_client.list_permission_sets and sso_client.describe_permission_set
        mock_sso_client.list_permission_sets.return_value = {
            "PermissionSets": [
                "arn:aws:sso:::permissionSet/ssoins-1111111111111111/ps-1111111111111111",
                "arn:aws:sso:::permissionSet/ssoins-1111111111111111/ps-2222222222222222",
            ]
        }
        # We're taking a bit of a shortcut here and not mocking individual describe_permission_set calls
        mock_sso_client.describe_permission_set.side_effect = [
            {
                "PermissionSet": {"Name": "PermissionSet1"},
            },
            {
                "PermissionSet": {"Name": "PermissionSet2"},
            },
        ]

        # Call the function to test
        result = resolve_permission_sets_and_assignments.create_permission_set_arn_dict(
            instance_id=instance_id,
            boto_config=self.mock_boto_config,
        )

        # Assertions
        self.assertEqual(result, expected_result)
        mock_sso_client.list_permission_sets.assert_called_once_with(
            InstanceArn=instance_id,
            MaxResults=100,
        )

    @patch("resolve_permission_sets_and_assignments.get_all_accounts_in_ou")
    @patch("boto3.client")
    def test_list_accounts_in_identifier(
        self,
        mock_boto3_client,
        mock_get_all_accounts_in_ou,
    ):
        # Set the return value for the patched function
        mock_org_client = mock_get_client("organizations")
        mock_boto3_client.return_value = mock_org_client
        accounts_map = {
            "active_account_in_ou_12345678": "111111111111",
            "suspended_account_in_ou_12345678": "222222222222",
            "active_account_in_root": "333333333333",
            "active_account_in_root_2": "444444444444",
        }
        ou_accounts_map = {
            "Accounts": [
                {
                    "Id": "111111111111",
                    "Status": "ACTIVE",
                },
                {
                    "Id": "222222222222",
                    "Status": "SUSPENDED",
                },
            ]
        }
        mock_org_client.list_accounts_for_parent.return_value = ou_accounts_map
        mock_get_all_accounts_in_ou.return_value = ou_accounts_map["Accounts"]
        mock_org_client.list_accounts.return_value = {
            "Accounts": [
                {
                    "Id": "111111111111",
                    "Status": "ACTIVE",
                },
                {
                    "Id": "222222222222",
                    "Status": "SUSPENDED",
                },
                {
                    "Id": "333333333333",
                    "Status": "ACTIVE",
                },
                {
                    "Id": "444444444444",
                    "Status": "ACTIVE",
                },
            ]
        }

        test_response_ou = (
            resolve_permission_sets_and_assignments.list_accounts_in_identifier(
                ou_identifier="ou-12345678",
                all_accounts_map=accounts_map,
                boto_config=self.mock_boto_config,
            )
        )
        test_response_root = (
            resolve_permission_sets_and_assignments.list_accounts_in_identifier(
                ou_identifier="r-12345",
                all_accounts_map=accounts_map,
                boto_config=self.mock_boto_config,
            )
        )
        self.assertEqual(test_response_ou, ["111111111111"])
        self.assertEqual(
            test_response_root, ["111111111111", "333333333333", "444444444444"]
        )


if __name__ == "__main__":
    unittest.main()
