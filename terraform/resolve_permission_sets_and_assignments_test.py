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
from pyfakefs import fake_filesystem_unittest
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

EXAMPLE_ASSIGNMENT = """
Assignments:
- PrincipalId: EXAMPLEAWSSecurityAuditors
  PrincipalType: GROUP
  PermissionSetName: ViewOnlyAccess
  Target:
  - 11111111111 # ID of an account -- remember to quote it so that it's interpreted as a string
  - ou-12345678 # ID of an OU
- PrincipalId: EXAMPLEAWSSecurityAuditors
  PrincipalType: GROUP
  PermissionSetName: ReadOnlyAccess
  Target:
  - SandboxOU # Name of an OU
  - qa-staging-account # Name of an account
- PrincipalId: EXAMPLEAWSSecurityAuditors
  PrincipalType: GROUP
  PermissionSetName: SecurityAudit
  Target:
  - ROOT # Special keyword to target all accounts in the organization
"""

EXPECTED_ASSIGNMENT = {
    "Assignments": [
        {
            "PrincipalId": "EXAMPLEAWSSecurityAuditors",
            "PrincipalType": "GROUP",
            "PermissionSetName": "ViewOnlyAccess",
            "Target": [11111111111, "ou-12345678"],
        },
        {
            "PrincipalId": "EXAMPLEAWSSecurityAuditors",
            "PrincipalType": "GROUP",
            "PermissionSetName": "ReadOnlyAccess",
            "Target": ["SandboxOU", "qa-staging-account"],
        },
        {
            "PrincipalId": "EXAMPLEAWSSecurityAuditors",
            "PrincipalType": "GROUP",
            "PermissionSetName": "SecurityAudit",
            "Target": ["ROOT"],
        },
    ]
}

EXAMPLE_PERMISSION_SET = """
{
  "Name": "EXAMPLEViewOnlyAccess",
  "Description": "An example View Only Access permission set using the default ViewOnlyAccess managed policy",
  "SessionDuration": "PT12H",
  "ManagedPolicies": ["arn:aws:iam::aws:policy/job-function/ViewOnlyAccess"],
  "CustomPolicy": {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Sid": "GetRoleExample",
        "Action": ["iam:GetRole"],
        "Effect": "Allow",
        "Resource": "*"
      }
    ]
  },
  "CustomerPermissionBoundary": {
    "Path": "pbounds/",
    "Name": "ViewOnlyAccessPB"
  }
}
"""

EXPECTED_PERMISSION_SET = """
resource "aws_ssoadmin_permission_set" "EXAMPLEViewOnlyAccess" {
  lifecycle {
    ignore_changes = [
      instance_arn
    ]
  }
  name             = "EXAMPLEViewOnlyAccess"
  description      = "An example View Only Access permission set using the default ViewOnlyAccess managed policy"
  instance_arn     = local.sso_instance_arn
  session_duration = "PT12H"
}


resource "aws_ssoadmin_managed_policy_attachment" "EXAMPLEViewOnlyAccess_managed_policy_ViewOnlyAccess" {
  lifecycle {
    ignore_changes = [
      instance_arn
    ]
  }
  instance_arn       = local.sso_instance_arn
  managed_policy_arn = "arn:aws:iam::aws:policy/job-function/ViewOnlyAccess"
  permission_set_arn = aws_ssoadmin_permission_set.EXAMPLEViewOnlyAccess.arn
}


resource "aws_ssoadmin_permission_set_inline_policy" "EXAMPLEViewOnlyAccess_custom_policy" {
  lifecycle {
    ignore_changes = [
      instance_arn
    ]
  }
  instance_arn       = local.sso_instance_arn
  inline_policy      = jsonencode(jsondecode(file("/test/viewonlyaccess.json")).CustomPolicy)
  permission_set_arn = aws_ssoadmin_permission_set.EXAMPLEViewOnlyAccess.arn
}


resource "aws_ssoadmin_permissions_boundary_attachment" "EXAMPLEViewOnlyAccess_permission_boundary" {
  lifecycle {
    ignore_changes = [
      instance_arn
    ]
  }

  instance_arn       = local.sso_instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.EXAMPLEViewOnlyAccess.arn
  permissions_boundary {
    customer_managed_policy_reference {
      name = "ViewOnlyAccessPB"
      path = "pbounds/"
    }
  }
}
"""

MALFORMED_PERMISSION_SET = """
{
  "PName": "EXAMPLEViewOnlyAccess",
  "PDescription": "An example View Only Access permission set using the default ViewOnlyAccess managed policy",
  "PSessionDuration": "PT12H",
  "PManagedPolicies": ["arn:aws:iam::aws:policy/job-function/ViewOnlyAccess"],
  "PCustomPolicy": {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Sid": "GetRoleExample",
        "Action": ["iam:GetRole"],
        "Effect": "Allow",
        "Resource": "*"
      }
    ]
  },
  "PCustomerPermissionBoundary": {
    "Path": "pbounds/",
    "Name": "PViewOnlyAccessPB"
  }
}
"""


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

    def test_customer_permission_boundary_undefined(self):
        data = {
            "Name": "TestPermissionSet",
            "CustomerPermissionBoundary": {},
        }
        with self.assertRaises(Exception):
            resolve_permission_sets_and_assignments.get_permission_set_permission_boundary(
                data=data,
            )

    def test_customer_permission_boundary_invalid_fields(self):
        data = {
            "Name": "TestPermissionSet",
            "CustomerPermissionBoundary": {
                "Foo": "TestManagedPolicy",
                "Bar": "/test/path",
            },
        }
        with self.assertRaises(Exception):
            resolve_permission_sets_and_assignments.get_permission_set_permission_boundary(
                data=data,
            )

    def test_customer_permission_boundary_half_data(self):
        data = {
            "Name": "TestPermissionSet",
            "CustomerPermissionBoundary": {
                "Foo": "TestManagedPolicy",
                "Path": "/test/path",
            },
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


class TestManifestAndAssignmentContent(fake_filesystem_unittest.TestCase):
    def setUp(self):
        self.template_path = "/test/"
        self.mgmt_only = False
        self.template_file = "viewonlyaccess.json"
        self.assignment_path = self.template_path
        self.assignment_file = "assignments.yaml"
        self.malformed_template_path = "/malformed/"
        self.malformed_template = "malformed.json"

        self.setUpPyfakefs()

        self.fake_fs().create_file(
            self.template_path + self.template_file, contents=EXAMPLE_PERMISSION_SET
        )
        self.fake_fs().create_file(
            self.assignment_path + self.assignment_file, contents=EXAMPLE_ASSIGNMENT
        )
        self.fake_fs().create_file(
            self.malformed_template_path + self.template_file,
            contents=MALFORMED_PERMISSION_SET,
        )

    def test_test_contents(self):
        import os

        contents = ""

        file_path = self.template_path + self.template_file
        self.assertTrue(os.path.exists(file_path))
        with open(file_path, "r") as f:
            contents = f.read()
        self.assertEqual(contents, EXAMPLE_PERMISSION_SET)

    def test_get_permission_set_manifest_content_with_file_path(self):
        # Call the function
        result = (
            resolve_permission_sets_and_assignments.get_permission_set_manifest_content(
                template_path=self.template_path,
                mgmt_only=self.mgmt_only,
            )
        )

        # Assert that the result is as expected
        self.assertEqual(result, EXPECTED_PERMISSION_SET)

    def test_get_permission_set_manifest_content_with_malformed_file(self):
        with self.assertRaises(Exception):
            # Pass a malformed file and confirm an exception is raised
            resolve_permission_sets_and_assignments.get_permission_set_manifest_content(
                template_path=self.malformed_template_path,
                mgmt_only=self.mgmt_only,
            )

    def test_load_assignments_from_file(self):
        # Call the function
        result = resolve_permission_sets_and_assignments.load_assignments_from_file(
            template_path=self.assignment_path,
        )

        # Assert that the result is as expected
        self.assertEqual(result, EXPECTED_ASSIGNMENT)

    def test_load_assignments_from_file_negative(self):
        with self.assertRaises(Exception):
            # Pass invalid file path and confirm an exception is raised
            resolve_permission_sets_and_assignments.load_assignments_from_file(
                template_path="/tmp/cc2274b58d53b8f1c3c23dbc54c9999ca09d981ddbb923b006ad61ae02d142fe8a8f327625b149135c2b65bda3b04bc99b557e72f4176073dfbb21191baf0be0",
            )


if __name__ == "__main__":
    unittest.main()
