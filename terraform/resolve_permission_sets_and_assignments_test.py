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
from validation import identifiers
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
  - '111111111111' # ID of an account -- remember to quote it so that it's interpreted as a string
  - ou-1234-12345678 # ID of an OU
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
            "Target": ["111111111111", "ou-1234-12345678"],
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
    "Path": "/pbounds/",
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
      path = "/pbounds/"
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
    "Path": "/pbounds/",
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

    def build_ou_client(self, children_by_parent):
        """
        Builds a mock Organizations client for resolve_ou_names.

        :param children_by_parent: Maps a parent ID to a list of response pages. Each
            page is a list of child OU IDs.
        """

        def list_organizational_units_for_parent(ParentId, NextToken=None):
            pages = children_by_parent.get(ParentId, [[]])
            index = int(NextToken) if NextToken else 0
            response = {
                "OrganizationalUnits": [{"Id": ou_id} for ou_id in pages[index]]
            }
            if index + 1 < len(pages):
                response["NextToken"] = str(index + 1)
            return response

        mock_client = MagicMock()
        mock_client.list_organizational_units_for_parent.side_effect = (
            list_organizational_units_for_parent
        )
        mock_client.describe_organizational_unit.side_effect = (
            lambda OrganizationalUnitId: {
                "OrganizationalUnit": {
                    "Id": OrganizationalUnitId,
                    "Name": f"name-of-{OrganizationalUnitId}",
                }
            }
        )
        return mock_client

    def test_resolve_ou_names_walks_every_depth(self):
        """
        This recursion is what makes an OU target include every account below the OU,
        at any depth.
        """
        mock_client = self.build_ou_client(
            {
                "ou-1234-aaaaaaaa": [["ou-1234-bbbbbbbb"]],
                "ou-1234-bbbbbbbb": [["ou-1234-cccccccc"]],
            }
        )

        result = resolve_permission_sets_and_assignments.resolve_ou_names(
            "ou-1234-aaaaaaaa", mock_client
        )

        self.assertEqual(
            [each_ou["Id"] for each_ou in result],
            ["ou-1234-aaaaaaaa", "ou-1234-bbbbbbbb", "ou-1234-cccccccc"],
        )
        self.assertEqual(result[0]["Name"], "name-of-ou-1234-aaaaaaaa")

    def test_resolve_ou_names_does_not_include_the_root(self):
        """
        The root is not an OU, so describe_organizational_unit cannot be called for it.
        """
        mock_client = self.build_ou_client({"r-1234": [["ou-1234-aaaaaaaa"]]})

        result = resolve_permission_sets_and_assignments.resolve_ou_names(
            "r-1234", mock_client
        )

        self.assertEqual([each_ou["Id"] for each_ou in result], ["ou-1234-aaaaaaaa"])
        mock_client.describe_organizational_unit.assert_called_once_with(
            OrganizationalUnitId="ou-1234-aaaaaaaa"
        )

    def test_resolve_ou_names_reads_every_page_of_children(self):
        mock_client = self.build_ou_client(
            {
                "ou-1234-aaaaaaaa": [
                    ["ou-1234-bbbbbbbb"],
                    ["ou-1234-cccccccc"],
                ],
            }
        )

        result = resolve_permission_sets_and_assignments.resolve_ou_names(
            "ou-1234-aaaaaaaa", mock_client
        )

        self.assertEqual(
            [each_ou["Id"] for each_ou in result],
            ["ou-1234-aaaaaaaa", "ou-1234-bbbbbbbb", "ou-1234-cccccccc"],
        )

    def test_resolve_ou_names_raises_when_an_ou_cannot_be_described(self):
        mock_client = self.build_ou_client({})
        mock_client.describe_organizational_unit.side_effect = Exception("not found")

        with self.assertRaises(Exception) as context:
            resolve_permission_sets_and_assignments.resolve_ou_names(
                "ou-1234-aaaaaaaa", mock_client
            )

        self.assertIn("ou-1234-aaaaaaaa", str(context.exception))

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
        # all_accounts_map maps an account name to a dict of its ID and its tags,
        # matching what create_assignments_manifest_from_repo_assignments builds.
        accounts_map = {
            "active_account_in_ou_12345678": {"id": "111111111111", "tags": []},
            # commented out as this function now expects only active accounts
            # "suspended_account_in_ou_12345678": {"id": "222222222222", "tags": []},
            "active_account_in_root": {"id": "333333333333", "tags": []},
            "active_account_in_root_2": {"id": "444444444444", "tags": []},
        }
        ou_accounts_map = {
            "Accounts": [
                {
                    "Id": "111111111111",
                    "State": "ACTIVE",
                },
                {
                    "Id": "222222222222",
                    "State": "SUSPENDED",
                },
            ]
        }
        mock_org_client.list_accounts_for_parent.return_value = ou_accounts_map
        mock_get_all_accounts_in_ou.return_value = ou_accounts_map["Accounts"]
        mock_org_client.list_accounts.return_value = {
            "Accounts": [
                {
                    "Id": "111111111111",
                    "State": "ACTIVE",
                },
                {
                    "Id": "222222222222",
                    "State": "SUSPENDED",
                },
                {
                    "Id": "333333333333",
                    "State": "ACTIVE",
                },
                {
                    "Id": "444444444444",
                    "State": "ACTIVE",
                },
            ]
        }

        test_response_ou, _ = (
            resolve_permission_sets_and_assignments.list_accounts_in_identifier(
                identifier="ou-1234-12345678",
                all_accounts_map=accounts_map,
                all_ous_map={},
                boto_config=self.mock_boto_config,
                identifier_cache={},
            )
        )
        test_response_root, _ = (
            resolve_permission_sets_and_assignments.list_accounts_in_identifier(
                identifier="r-12345",
                all_accounts_map=accounts_map,
                all_ous_map={},
                boto_config=self.mock_boto_config,
                identifier_cache={},
            )
        )
        self.assertEqual(test_response_ou, ["111111111111"])
        self.assertEqual(
            test_response_root, ["111111111111", "333333333333", "444444444444"]
        )

    @patch("resolve_permission_sets_and_assignments.get_all_accounts_in_ou")
    @patch("boto3.client")
    def test_list_accounts_in_identifier_ou_name_containing_r_dash_is_not_root(
        self,
        mock_boto3_client,
        mock_get_all_accounts_in_ou,
    ):
        """
        An OU or account name that merely contains "r-" must not be treated as the
        organization root. A substring test for "r-" expanded such a name to every
        account in the organization.
        """
        mock_boto3_client.return_value = mock_get_client("organizations")
        accounts_map = {
            "account_in_prod_r_us": {"id": "111111111111", "tags": []},
            "unrelated_account": {"id": "333333333333", "tags": []},
            "unrelated_account_2": {"id": "444444444444", "tags": []},
        }
        mock_get_all_accounts_in_ou.return_value = [
            {"Id": "111111111111", "State": "ACTIVE"},
        ]

        result, _ = resolve_permission_sets_and_assignments.list_accounts_in_identifier(
            identifier="prod-r-us",
            all_accounts_map=accounts_map,
            all_ous_map={"prod-r-us": [{"Id": "ou-1234-12345678"}]},
            boto_config=self.mock_boto_config,
            identifier_cache={},
        )

        self.assertEqual(result, ["111111111111"])

    @patch("boto3.client")
    def test_list_accounts_in_identifier_account_name_containing_r_dash_is_not_root(
        self,
        mock_boto3_client,
    ):
        mock_boto3_client.return_value = mock_get_client("organizations")
        accounts_map = {
            "prod-r-us": {"id": "111111111111", "tags": []},
            "unrelated_account": {"id": "333333333333", "tags": []},
        }

        result, _ = resolve_permission_sets_and_assignments.list_accounts_in_identifier(
            identifier="prod-r-us",
            all_accounts_map=accounts_map,
            all_ous_map={},
            boto_config=self.mock_boto_config,
            identifier_cache={},
        )

        self.assertEqual(result, ["111111111111"])

    @patch("boto3.client")
    def test_list_accounts_in_identifier_account_name_starting_with_ou_is_not_an_ou_id(
        self,
        mock_boto3_client,
    ):
        """
        A test for the "ou-" prefix alone sent any name that starts with "ou-" to the
        Organizations API as an OU ID. Such a name must be resolved as a name.
        """
        mock_boto3_client.return_value = mock_get_client("organizations")
        accounts_map = {
            "ou-my-team-account": {"id": "111111111111", "tags": []},
            "unrelated_account": {"id": "333333333333", "tags": []},
        }

        result, _ = resolve_permission_sets_and_assignments.list_accounts_in_identifier(
            identifier="ou-my-team-account",
            all_accounts_map=accounts_map,
            all_ous_map={},
            boto_config=self.mock_boto_config,
            identifier_cache={},
        )

        self.assertEqual(result, ["111111111111"])

    @patch("boto3.client")
    def test_list_accounts_in_identifier_rejects_an_ambiguous_name(
        self,
        mock_boto3_client,
    ):
        """
        An AWS account name can hold any printable character, so an account or an OU can
        be named "ROOT", or named to look like a root ID or an OU ID. Reading such a
        name as an ID grants access to every account in the organization, so the
        resolver must refuse to guess.
        """
        mock_boto3_client.return_value = mock_get_client("organizations")
        for identifier, accounts_map, ous_map in [
            ("ROOT", {"ROOT": {"id": "111111111111", "tags": []}}, {}),
            ("Root", {"Root": {"id": "111111111111", "tags": []}}, {}),
            ("r-abcd", {"r-abcd": {"id": "111111111111", "tags": []}}, {}),
            ("ROOT", {}, {"ROOT": [{"Id": "ou-1234-12345678"}]}),
            (
                "ou-abcd-12345678",
                {"ou-abcd-12345678": {"id": "111111111111", "tags": []}},
                {},
            ),
        ]:
            with self.assertRaises(Exception) as context:
                resolve_permission_sets_and_assignments.list_accounts_in_identifier(
                    identifier=identifier,
                    all_accounts_map=accounts_map,
                    all_ous_map=ous_map,
                    boto_config=self.mock_boto_config,
                    identifier_cache={},
                )
            self.assertIn(identifier, str(context.exception))
            self.assertIn("target it by its ID", str(context.exception))

    @patch("resolve_permission_sets_and_assignments.list_accounts_in_identifier")
    def test_resolve_targets_rejects_an_account_named_like_an_account_id(
        self,
        mock_list_accounts_in_identifier,
    ):
        """
        An account can be named with 12 digits. Such a target can be the name of one
        account and the ID of another.
        """
        assignment = {
            "Target": ["111111111111"],
            "PrincipalId": "SomeGroup",
            "PermissionSetName": "SomePermissionSet",
        }

        with self.assertRaises(Exception) as context:
            resolve_permission_sets_and_assignments.resolve_targets(
                each_current_assignments=assignment,
                all_accounts_map={"111111111111": {"id": "222222222222", "tags": []}},
                all_ous_map={},
                boto_config=self.mock_boto_config,
                identifier_cache={},
            )

        # The message names the ID of the account that carries the confusing name
        self.assertIn("222222222222", str(context.exception))

    @patch("boto3.client")
    def test_list_accounts_in_identifier_literal_root_still_matches(
        self,
        mock_boto3_client,
    ):
        """Guards against over-tightening the root match."""
        mock_boto3_client.return_value = mock_get_client("organizations")
        accounts_map = {
            "account_one": {"id": "111111111111", "tags": []},
            "account_two": {"id": "333333333333", "tags": []},
        }

        for identifier in ["ROOT", "Root", "r-1234"]:
            result, _ = (
                resolve_permission_sets_and_assignments.list_accounts_in_identifier(
                    identifier=identifier,
                    all_accounts_map=accounts_map,
                    all_ous_map={},
                    boto_config=self.mock_boto_config,
                    identifier_cache={},
                )
            )
            self.assertEqual(
                result,
                ["111111111111", "333333333333"],
                f"identifier {identifier} should resolve to all accounts",
            )

    @patch("resolve_permission_sets_and_assignments.resolve_ou_names")
    def test_get_all_accounts_in_ou_paginates_against_each_ou(
        self,
        mock_resolve_ou_names,
    ):
        """
        Each OU must be paginated against its own ID. An earlier version passed the
        original ou_id for every page after the first, so accounts from a different
        OU were returned.
        """
        mock_resolve_ou_names.return_value = [
            {"Id": "ou-1234-aaaaaaaa"},
            {"Id": "ou-1234-bbbbbbbb"},
        ]
        pages_by_parent = {
            # Two pages, to exercise pagination
            "ou-1234-aaaaaaaa": [
                {"Accounts": [{"Id": "111111111111", "State": "ACTIVE"}]},
                {"Accounts": [{"Id": "222222222222", "State": "ACTIVE"}]},
            ],
            "ou-1234-bbbbbbbb": [
                {"Accounts": [{"Id": "333333333333", "State": "ACTIVE"}]},
            ],
        }
        mock_client = MagicMock()
        mock_paginator = MagicMock()
        mock_paginator.paginate.side_effect = lambda ParentId: pages_by_parent[ParentId]
        mock_client.get_paginator.return_value = mock_paginator

        result = resolve_permission_sets_and_assignments.get_all_accounts_in_ou(
            ou_id="ou-1234-aaaaaaaa",
            client=mock_client,
        )

        self.assertEqual(
            [each_account["Id"] for each_account in result],
            ["111111111111", "222222222222", "333333333333"],
        )
        self.assertEqual(
            [call.kwargs["ParentId"] for call in mock_paginator.paginate.call_args_list],
            ["ou-1234-aaaaaaaa", "ou-1234-bbbbbbbb"],
        )

    @patch("resolve_permission_sets_and_assignments.resolve_ou_names")
    def test_get_all_accounts_in_ou_skips_inactive_accounts(
        self,
        mock_resolve_ou_names,
    ):
        mock_resolve_ou_names.return_value = [{"Id": "ou-1234-aaaaaaaa"}]
        mock_client = MagicMock()
        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [
            {
                "Accounts": [
                    {"Id": "111111111111", "State": "ACTIVE"},
                    {"Id": "222222222222", "State": "SUSPENDED"},
                ]
            },
            {"Accounts": [{"Id": "333333333333", "State": "SUSPENDED"}]},
        ]
        mock_client.get_paginator.return_value = mock_paginator

        result = resolve_permission_sets_and_assignments.get_all_accounts_in_ou(
            ou_id="ou-1234-aaaaaaaa",
            client=mock_client,
        )

        self.assertEqual([each_account["Id"] for each_account in result], ["111111111111"])

    @patch("resolve_permission_sets_and_assignments.list_accounts_in_identifier")
    def test_resolve_targets_account_id_is_used_without_a_lookup(
        self,
        mock_list_accounts_in_identifier,
    ):
        assignment = {
            "Target": ["111111111111"],
            "PrincipalId": "SomeGroup",
            "PermissionSetName": "SomePermissionSet",
        }

        result, _ = resolve_permission_sets_and_assignments.resolve_targets(
            each_current_assignments=assignment,
            all_accounts_map={},
            all_ous_map={},
            boto_config=self.mock_boto_config,
            identifier_cache={},
        )

        self.assertEqual(result, ["111111111111"])
        mock_list_accounts_in_identifier.assert_not_called()

    @patch("resolve_permission_sets_and_assignments.list_accounts_in_identifier")
    def test_resolve_targets_digit_strings_that_are_not_account_ids_are_looked_up(
        self,
        mock_list_accounts_in_identifier,
    ):
        """
        The account ID test must match the whole string. An unanchored match treated a
        13 digit string, and a name beginning with 12 digits, as account IDs and used
        them with no lookup at all.
        """
        mock_list_accounts_in_identifier.return_value = (["999999999999"], {})
        for target in ["1234567890123", "111111111111-sandbox", "11111111111"]:
            mock_list_accounts_in_identifier.reset_mock()
            assignment = {
                "Target": [target],
                "PrincipalId": "SomeGroup",
                "PermissionSetName": "SomePermissionSet",
            }

            result, _ = resolve_permission_sets_and_assignments.resolve_targets(
                each_current_assignments=assignment,
                all_accounts_map={},
                all_ous_map={},
                boto_config=self.mock_boto_config,
                identifier_cache={},
            )

            self.assertEqual(result, ["999999999999"])
            self.assertEqual(
                mock_list_accounts_in_identifier.call_args.kwargs["identifier"],
                target,
            )

    @patch("resolve_permission_sets_and_assignments.list_accounts_in_identifier")
    def test_resolve_targets_exclusions(
        self,
        mock_list_accounts_in_identifier,
    ):
        mock_list_accounts_in_identifier.return_value = (
            ["111111111111", "222222222222", "333333333333"],
            {},
        )
        assignment = {
            "Target": ["SomeOU"],
            "Exclusions": ["222222222222"],
            "PrincipalId": "SomeGroup",
            "PermissionSetName": "SomePermissionSet",
        }

        result, _ = resolve_permission_sets_and_assignments.resolve_targets(
            each_current_assignments=assignment,
            all_accounts_map={},
            all_ous_map={},
            boto_config=self.mock_boto_config,
            identifier_cache={},
        )

        self.assertEqual(result, ["111111111111", "333333333333"])

    @patch("resolve_permission_sets_and_assignments.list_accounts_in_identifier")
    def test_resolve_targets_exclusion_that_is_not_present_is_a_noop(
        self,
        mock_list_accounts_in_identifier,
    ):
        mock_list_accounts_in_identifier.return_value = (["111111111111"], {})
        assignment = {
            "Target": ["SomeOU"],
            "Exclusions": ["999999999999"],
            "PrincipalId": "SomeGroup",
            "PermissionSetName": "SomePermissionSet",
        }

        result, _ = resolve_permission_sets_and_assignments.resolve_targets(
            each_current_assignments=assignment,
            all_accounts_map={},
            all_ous_map={},
            boto_config=self.mock_boto_config,
            identifier_cache={},
        )

        self.assertEqual(result, ["111111111111"])

    @patch("boto3.client")
    def test_lookup_principal_id_group_and_user(self, mock_boto3_client):
        mock_id_store = mock_get_client("identitystore")
        mock_id_store.reset_mock()
        mock_boto3_client.return_value = mock_id_store
        mock_id_store.list_groups.return_value = {"Groups": [{"GroupId": "group-1"}]}
        mock_id_store.list_users.return_value = {"Users": [{"UserId": "user-1"}]}

        group_id, cache = resolve_permission_sets_and_assignments.lookup_principal_id(
            "SomeGroup",
            "GROUP",
            identity_store_id="d-1234567890",
            boto_config=self.mock_boto_config,
            principal_cache={},
        )
        user_id, cache = resolve_permission_sets_and_assignments.lookup_principal_id(
            "SomeUser",
            "USER",
            identity_store_id="d-1234567890",
            boto_config=self.mock_boto_config,
            principal_cache=cache,
        )

        self.assertEqual(group_id, "group-1")
        self.assertEqual(user_id, "user-1")
        self.assertEqual(cache, {"GROUP|SomeGroup": "group-1", "USER|SomeUser": "user-1"})

        # A second lookup of a cached principal must not call the API again
        mock_id_store.list_groups.reset_mock()
        cached_id, _ = resolve_permission_sets_and_assignments.lookup_principal_id(
            "SomeGroup",
            "GROUP",
            identity_store_id="d-1234567890",
            boto_config=self.mock_boto_config,
            principal_cache=cache,
        )
        self.assertEqual(cached_id, "group-1")
        mock_id_store.list_groups.assert_not_called()

    @patch("boto3.client")
    def test_lookup_principal_id_raises_when_no_match(self, mock_boto3_client):
        """
        A failed lookup previously fell off the end of the function and returned None,
        which the caller unpacked into two names, producing an unrelated TypeError
        traceback that hid the real cause.
        """
        mock_id_store = mock_get_client("identitystore")
        mock_id_store.reset_mock()
        mock_boto3_client.return_value = mock_id_store
        mock_id_store.list_groups.return_value = {"Groups": []}

        with self.assertRaises(Exception) as context:
            resolve_permission_sets_and_assignments.lookup_principal_id(
                "TypoedGroupName",
                "GROUP",
                identity_store_id="d-1234567890",
                boto_config=self.mock_boto_config,
                principal_cache={},
            )

        self.assertIn("TypoedGroupName", str(context.exception))
        self.assertIn("GROUP", str(context.exception))

    @patch("boto3.client")
    def test_lookup_principal_id_raises_on_duplicate_matches(self, mock_boto3_client):
        mock_id_store = mock_get_client("identitystore")
        mock_id_store.reset_mock()
        mock_boto3_client.return_value = mock_id_store
        mock_id_store.list_users.return_value = {
            "Users": [{"UserId": "user-1"}, {"UserId": "user-2"}]
        }

        with self.assertRaises(Exception) as context:
            resolve_permission_sets_and_assignments.lookup_principal_id(
                "AmbiguousUser",
                "USER",
                identity_store_id="d-1234567890",
                boto_config=self.mock_boto_config,
                principal_cache={},
            )

        self.assertIn("AmbiguousUser", str(context.exception))

    @patch("boto3.client")
    def test_lookup_principal_id_raises_on_unsupported_principal_type(
        self, mock_boto3_client
    ):
        """An unrecognised PrincipalType previously returned None with no log at all."""
        mock_boto3_client.return_value = mock_get_client("identitystore")

        with self.assertRaises(Exception) as context:
            resolve_permission_sets_and_assignments.lookup_principal_id(
                "SomeGroup",
                "group",  # lowercase: not a valid PrincipalType
                identity_store_id="d-1234567890",
                boto_config=self.mock_boto_config,
                principal_cache={},
            )

        self.assertIn("group", str(context.exception))
        self.assertIn("PrincipalType", str(context.exception))

    def test_mgmt_only_flag_parsing(self):
        """
        --mgmt-only used type=bool, so any value (including "False") evaluated to True,
        and the default of False meant the MGMT_ONLY environment variable fallback was
        unreachable.
        """
        parser = resolve_permission_sets_and_assignments.build_arg_parser()
        self.assertIsNone(parser.parse_args([]).mgmt_only)
        self.assertTrue(parser.parse_args(["--mgmt-only"]).mgmt_only)
        self.assertFalse(parser.parse_args(["--no-mgmt-only"]).mgmt_only)


class TestIdentifiers(unittest.TestCase):
    """Tests for the shared identifier helpers in validation/identifiers.py."""

    def test_is_aws_account_id(self):
        for value in ["111111111111", "000000000001", 111111111111]:
            self.assertTrue(identifiers.is_aws_account_id(value), value)
        for value in [
            "1234567890123",  # too long: an unanchored match accepted this
            "11111111111",  # too short
            "111111111111-sandbox",  # name that starts with 12 digits
            "sandbox",
            "",
        ]:
            self.assertFalse(identifiers.is_aws_account_id(value), value)

    def test_is_organization_root_id(self):
        """
        The AWS Organizations pattern for a root ID is "r-" followed by 4 to 32
        lowercase letters or digits.
        """
        for value in ["r-1234", "r-abcd1234", "r-" + "a" * 32]:
            self.assertTrue(identifiers.is_organization_root_id(value), value)
        for value in [
            "prod-r-us",  # a name that contains "r-"
            "ROOT",
            "r-",  # no suffix
            "r-abc",  # fewer than 4 characters
            "r-ABCD",  # uppercase
            "r-" + "a" * 33,  # more than 32 characters
            "ou-1234-12345678",
        ]:
            self.assertFalse(identifiers.is_organization_root_id(value), value)

    def test_is_organizational_unit_id(self):
        """
        The AWS Organizations pattern for an OU ID is "ou-" followed by 4 to 32
        lowercase letters or digits, then a dash, then 8 to 32 more.
        """
        for value in ["ou-1234-12345678", "ou-abcd1234-abcdefgh1234"]:
            self.assertTrue(identifiers.is_organizational_unit_id(value), value)
        for value in [
            "ou-12345678",  # no root part
            "ou-1234-1234567",  # second part shorter than 8 characters
            "ou-abc-12345678",  # first part shorter than 4 characters
            "ou-1234-ABCDEFGH",  # uppercase
            "ou-1234-12345678-extra",
            "ou-my-team-account",  # a name that starts with "ou-"
            "r-1234",
        ]:
            self.assertFalse(identifiers.is_organizational_unit_id(value), value)

    def test_is_valid_terraform_identifier(self):
        for value in ["MyPermissionSet", "_leading_underscore", "a-b_c1"]:
            self.assertTrue(identifiers.is_valid_terraform_identifier(value), value)
        for value in ["1LeadingDigit", "-leading-dash", "has space", "has.dot", ""]:
            self.assertFalse(identifiers.is_valid_terraform_identifier(value), value)

    def test_parse_customer_managed_policy_reference(self):
        self.assertEqual(
            identifiers.parse_customer_managed_policy_reference("myPolicy"),
            ("/", "myPolicy"),
        )
        self.assertEqual(
            identifiers.parse_customer_managed_policy_reference("/sso/global/myPolicy"),
            ("/sso/global/", "myPolicy"),
        )
        # The path is returned as written, not normalised. Validation rejects a path
        # with no leading slash.
        self.assertEqual(
            identifiers.parse_customer_managed_policy_reference("sso/global/myPolicy"),
            ("sso/global/", "myPolicy"),
        )
        # An ARN is not a supported value: the template holds a policy name. It parses
        # to a path with no leading slash, which validation rejects.
        self.assertEqual(
            identifiers.parse_customer_managed_policy_reference(
                "arn:aws:iam::111111111111:policy/sso/myPolicy"
            ),
            ("policy/sso/", "myPolicy"),
        )


class TestAssignmentManifestGeneration(unittest.TestCase):
    """
    Tests for the generated assignment resources, and for the check that two
    assignments do not produce one Terraform resource name.
    """

    mock_boto_config = Config(retries={"max_attempts": 0})
    control_tower_permission_sets = ["AWSReadOnlyAccess"]

    def test_get_assignment_resource_name_does_not_change(self):
        """
        This is the guard for the decision to keep the existing resource names. The
        name is the Terraform address of a live resource. A change here makes Terraform
        destroy and create every assignment, which removes access while it does so.
        """
        self.assertEqual(
            resolve_permission_sets_and_assignments.get_assignment_resource_name(
                "111111111111",
                {
                    "PrincipalId": "a.b@example.com",
                    "PrincipalType": "USER",
                    "PermissionSetName": "ViewOnlyAccess",
                },
            ),
            "assignment_111111111111abexamplecomUSERViewOnlyAccess",
        )
        self.assertEqual(
            resolve_permission_sets_and_assignments.get_assignment_resource_name(
                "222222222222",
                {
                    "PrincipalId": "AWS-Security-Auditors",
                    "PrincipalType": "GROUP",
                    "PermissionSetName": "SecurityAudit",
                },
            ),
            "assignment_222222222222AWS-Security-AuditorsGROUPSecurityAudit",
        )

    def test_get_assignments_manifest_references_the_permission_set_resource(self):
        output = resolve_permission_sets_and_assignments.get_assignments_manifest(
            account="111111111111",
            assignment={
                "PrincipalId": "SomeGroup",
                "PrincipalType": "GROUP",
                "PermissionSetName": "ViewOnlyAccess",
            },
            principal_numeric_id="group-1",
            permission_set_arn_dict={},
            control_tower_permission_sets=self.control_tower_permission_sets,
        )
        self.assertIn(
            'resource "aws_ssoadmin_account_assignment" '
            '"assignment_111111111111SomeGroupGROUPViewOnlyAccess"',
            output,
        )
        self.assertIn(
            "permission_set_arn = aws_ssoadmin_permission_set.ViewOnlyAccess.arn",
            output,
        )

    def test_get_assignments_manifest_uses_a_literal_arn_for_control_tower(self):
        output = resolve_permission_sets_and_assignments.get_assignments_manifest(
            account="111111111111",
            assignment={
                "PrincipalId": "SomeGroup",
                "PrincipalType": "GROUP",
                "PermissionSetName": "AWSReadOnlyAccess",
            },
            principal_numeric_id="group-1",
            permission_set_arn_dict={"AWSReadOnlyAccess": "arn:aws:sso:::ps/example"},
            control_tower_permission_sets=self.control_tower_permission_sets,
        )
        self.assertIn('permission_set_arn = "arn:aws:sso:::ps/example"', output)

    def build_manifest(self, assignments, accounts_by_principal, mgmt_only=False):
        """
        Calls create_assignments_manifest_from_repo_assignments with the Organizations
        and Identity Store calls mocked out.
        """
        mock_org = MagicMock()
        mock_org.describe_organization.return_value = {
            "Organization": {"MasterAccountId": "999999999999"}
        }
        mock_org.list_accounts.return_value = {"Accounts": []}
        mock_org.list_roots.return_value = {"Roots": [{"Id": "r-1234"}]}

        def fake_resolve_targets(each_current_assignments, **kwargs):
            return accounts_by_principal[each_current_assignments["PrincipalId"]], {}

        def fake_lookup_principal_id(principal_name, principal_type, **kwargs):
            return f"id-of-{principal_name}", {}

        with patch("boto3.client", return_value=mock_org), patch(
            "resolve_permission_sets_and_assignments.get_all_ous_map", return_value={}
        ), patch(
            "resolve_permission_sets_and_assignments.resolve_targets",
            side_effect=fake_resolve_targets,
        ), patch(
            "resolve_permission_sets_and_assignments.lookup_principal_id",
            side_effect=fake_lookup_principal_id,
        ):
            return resolve_permission_sets_and_assignments.create_assignments_manifest_from_repo_assignments(
                repository_assignments={"Assignments": assignments},
                identity_store="d-1234567890",
                permission_set_name_dict={},
                mgmt_only=mgmt_only,
                control_tower_permission_sets=self.control_tower_permission_sets,
                boto_config=self.mock_boto_config,
            )

    def test_identical_assignments_are_deduplicated(self):
        """
        The same assignment can appear in more than one input file. One copy must reach
        the manifest, as the earlier set() gave.
        """
        assignment = {
            "PrincipalId": "SomeGroup",
            "PrincipalType": "GROUP",
            "PermissionSetName": "ViewOnlyAccess",
            "Target": ["111111111111"],
        }

        output = self.build_manifest(
            assignments=[assignment, dict(assignment)],
            accounts_by_principal={"SomeGroup": ["111111111111"]},
        )

        self.assertEqual(output.count("aws_ssoadmin_account_assignment"), 1)

    def test_a_resource_name_collision_raises(self):
        """
        Every character other than a letter, a digit, a dash or an underscore is
        removed from PrincipalId to build the resource name. Therefore two principals
        can give one name, and the generated manifest would hold the same resource
        name twice and would not parse.
        """
        assignments = [
            {
                "PrincipalId": "a.b@example.com",
                "PrincipalType": "USER",
                "PermissionSetName": "ViewOnlyAccess",
                "Target": ["111111111111"],
            },
            {
                "PrincipalId": "ab@example.com",
                "PrincipalType": "USER",
                "PermissionSetName": "ViewOnlyAccess",
                "Target": ["111111111111"],
            },
        ]

        with self.assertRaises(Exception) as context:
            self.build_manifest(
                assignments=assignments,
                accounts_by_principal={
                    "a.b@example.com": ["111111111111"],
                    "ab@example.com": ["111111111111"],
                },
            )

        self.assertIn("resource name", str(context.exception))

    def test_the_output_is_the_same_on_every_run(self):
        """
        The earlier code joined a set, so the order of the generated file changed
        between runs. A stable order makes the file easier to read while debugging.
        """
        assignments = [
            {
                "PrincipalId": f"Group{index}",
                "PrincipalType": "GROUP",
                "PermissionSetName": "ViewOnlyAccess",
                "Target": ["111111111111"],
            }
            for index in range(10)
        ]
        accounts_by_principal = {f"Group{index}": ["111111111111"] for index in range(10)}

        first = self.build_manifest(assignments, accounts_by_principal)
        second = self.build_manifest(assignments, accounts_by_principal)

        self.assertEqual(first, second)

    def test_management_account_assignments_are_separated(self):
        """
        A member account assignment must not be generated in management-only mode, and
        the reverse. This is the delegated administrator boundary.
        """
        assignments = [
            {
                "PrincipalId": "SomeGroup",
                "PrincipalType": "GROUP",
                "PermissionSetName": "ViewOnlyAccess",
                "Target": ["111111111111", "999999999999"],
            }
        ]
        accounts_by_principal = {"SomeGroup": ["111111111111", "999999999999"]}

        member_output = self.build_manifest(
            assignments, accounts_by_principal, mgmt_only=False
        )
        management_output = self.build_manifest(
            assignments, accounts_by_principal, mgmt_only=True
        )

        self.assertIn('target_id          = "111111111111"', member_output)
        self.assertNotIn('target_id          = "999999999999"', member_output)
        self.assertIn('target_id          = "999999999999"', management_output)
        self.assertNotIn('target_id          = "111111111111"', management_output)


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
