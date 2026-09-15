import unittest
from unittest.mock import patch, MagicMock
from botocore.exceptions import ClientError
from validation.iam_identitycenter_validation import (
    build_customer_policy_arn,
    validate_assignment_targets,
    validate_assignments,
    validate_customer_managed_policy_paths,
    validate_managed_policies_arn,
    validate_permission_set_names_are_terraform_identifiers,
    validate_permission_sets,
    validate_unique_permission_set_name,
)


def client_error(code: str) -> ClientError:
    """Builds a ClientError with the given error code, as boto3 would raise it."""
    return ClientError({"Error": {"Code": code, "Message": code}}, "GetPolicy")


class TestValidateUniquePermissionSetName(unittest.TestCase):

    def test_unique_permission_set_names(
        self,
    ):
        permission_set_templates = {
            "template1": {"Name": "PermissionSet1"},
            "template2": {"Name": "PermissionSet2"},
            "template3": {"Name": "PermissionSet3"},
        }
        result = validate_unique_permission_set_name(permission_set_templates)
        self.assertEqual(result, [])

    def test_duplicate_permission_set_names(
        self,
    ):
        permission_set_templates = {
            "template1": {"Name": "PermissionSet1"},
            "template2": {"Name": "PermissionSet2"},
            "template3": {"Name": "PermissionSet1"},
        }
        result = validate_unique_permission_set_name(permission_set_templates)
        self.assertEqual(len(result), 1)
        self.assertIn("Duplicate Permission Set Names", result[0])
        self.assertIn("PermissionSet1", result[0])

    def test_missing_name_key_raises(
        self,
    ):
        """
        A permission set file with no Name key cannot be checked for uniqueness, so
        this validator raises rather than returning an error string.
        """
        permission_set_templates = {"template1": {"Description": "No name here"}}
        with self.assertRaises(Exception) as context:
            validate_unique_permission_set_name(permission_set_templates)
        self.assertIn("template1", str(context.exception))


class TestBuildCustomerPolicyArn(unittest.TestCase):
    """
    An IAM policy ARN has exactly one slash between "policy" and the path. The old
    code concatenated a hard-coded slash with the Path from the template, so a
    correct Path of "/pbounds/" produced "policy//pbounds/" and only an incorrect
    Path with no leading slash produced a valid ARN.
    """

    def test_path_with_leading_and_trailing_slash(self):
        self.assertEqual(
            build_customer_policy_arn("123456789012", "/pbounds/", "MyPolicy"),
            "arn:aws:iam::123456789012:policy/pbounds/MyPolicy",
        )

    def test_path_without_slashes(self):
        self.assertEqual(
            build_customer_policy_arn("123456789012", "pbounds", "MyPolicy"),
            "arn:aws:iam::123456789012:policy/pbounds/MyPolicy",
        )

    def test_nested_path(self):
        self.assertEqual(
            build_customer_policy_arn("123456789012", "/sso/global/", "MyPolicy"),
            "arn:aws:iam::123456789012:policy/sso/global/MyPolicy",
        )

    def test_root_path(self):
        for path in ["/", "", None]:
            self.assertEqual(
                build_customer_policy_arn("123456789012", path, "MyPolicy"),
                "arn:aws:iam::123456789012:policy/MyPolicy",
                f"path {path!r}",
            )


class TestValidateManagedPoliciesArn(unittest.TestCase):

    @patch("boto3.client")
    def test_no_managed_policies_key(self, mock_boto3_client):
        """
        ManagedPolicies is optional: a permission set may use only CustomPolicy or
        only CustomerManagedPolicies. Reading the key directly raised a KeyError that
        the except ClientError block could not catch, so validation crashed.
        """
        mock_boto3_client.return_value = MagicMock()
        permission_set = {
            "Name": "InlineOnly",
            "CustomPolicy": {"Version": "2012-10-17", "Statement": []},
        }

        result = validate_managed_policies_arn(permission_set, "123456789012")

        self.assertEqual(result, [])

    @patch("boto3.client")
    def test_reports_every_missing_policy(self, mock_boto3_client):
        """
        The loop was inside the try block, so the first missing policy stopped the
        remaining policies from being checked.
        """
        mock_iam = MagicMock()
        mock_iam.get_policy.side_effect = [
            client_error("NoSuchEntity"),
            {"Policy": {}},
            client_error("NoSuchEntity"),
        ]
        mock_boto3_client.return_value = mock_iam
        permission_set = {
            "Name": "ThreePolicies",
            "ManagedPolicies": ["arn:one", "arn:two", "arn:three"],
        }

        result = validate_managed_policies_arn(permission_set, "123456789012")

        self.assertEqual(len(result), 2)
        self.assertIn("arn:one", result[0])
        self.assertIn("arn:three", result[1])

    @patch("boto3.client")
    def test_reraises_access_denied(self, mock_boto3_client):
        """
        A reported finding must mean "the template is wrong". If the validator cannot
        read IAM, it must fail loudly rather than report a missing policy.
        """
        mock_iam = MagicMock()
        mock_iam.get_policy.side_effect = client_error("AccessDenied")
        mock_boto3_client.return_value = mock_iam
        permission_set = {"Name": "Denied", "ManagedPolicies": ["arn:one"]}

        with self.assertRaises(ClientError):
            validate_managed_policies_arn(permission_set, "123456789012")

    @patch("boto3.client")
    def test_permission_boundary_without_a_path(self, mock_boto3_client):
        """
        Path is optional, and the resolver defaults a missing Path to "/". Reading the
        key directly raised a KeyError, so validation rejected input that the resolver
        accepts.
        """
        mock_iam = MagicMock()
        mock_iam.get_policy.return_value = {"Policy": {}}
        mock_boto3_client.return_value = mock_iam
        permission_set = {
            "Name": "BoundaryNoPath",
            "CustomerPermissionBoundary": {"Name": "MyBoundary"},
        }

        result = validate_managed_policies_arn(permission_set, "123456789012")

        self.assertEqual(result, [])
        mock_iam.get_policy.assert_called_once_with(
            PolicyArn="arn:aws:iam::123456789012:policy/MyBoundary"
        )

    @patch("boto3.client")
    def test_permission_boundary_arn_has_a_single_slash(self, mock_boto3_client):
        mock_iam = MagicMock()
        mock_iam.get_policy.return_value = {"Policy": {}}
        mock_boto3_client.return_value = mock_iam
        permission_set = {
            "Name": "BoundaryWithPath",
            "CustomerPermissionBoundary": {"Path": "/pbounds/", "Name": "MyBoundary"},
        }

        result = validate_managed_policies_arn(permission_set, "123456789012")

        self.assertEqual(result, [])
        mock_iam.get_policy.assert_called_once_with(
            PolicyArn="arn:aws:iam::123456789012:policy/pbounds/MyBoundary"
        )

    @patch("boto3.client")
    def test_permission_boundary_arn_instead_of_name(self, mock_boto3_client):
        mock_boto3_client.return_value = MagicMock()
        permission_set = {
            "Name": "BoundaryArn",
            "CustomerPermissionBoundary": {
                "Name": "arn:aws:iam::123456789012:policy/MyBoundary"
            },
        }

        result = validate_managed_policies_arn(permission_set, "123456789012")

        self.assertEqual(len(result), 1)
        self.assertIn("instead of name", result[0])


class TestValidatePermissionSetNamesAreTerraformIdentifiers(unittest.TestCase):
    """
    The permission set Name is written into six Terraform resource labels and
    references. A Name that Terraform does not accept gives a generated manifest that
    does not parse, and that manifest is not in the repository.
    """

    def test_valid_names(self):
        templates = {
            "a.json": {"Name": "MyPermissionSet"},
            "b.json": {"Name": "_internal"},
            "c.json": {"Name": "read-only_1"},
        }
        self.assertEqual(
            validate_permission_set_names_are_terraform_identifiers(templates), []
        )

    def test_invalid_names(self):
        for name in ["My Permission Set", "my.pset", "1Pset", "-pset", ""]:
            result = validate_permission_set_names_are_terraform_identifiers(
                {"bad.json": {"Name": name}}
            )
            self.assertEqual(len(result), 1, f"name {name!r}")
            self.assertIn("bad.json", result[0])
            self.assertIn(name, result[0])


class TestValidateCustomerManagedPolicyPaths(unittest.TestCase):
    """
    AWS requires a policy path to start with a slash. It rejects a path without one at
    apply time, which is after review and after merge.
    """

    def test_a_plain_policy_name_is_valid(self):
        template = {"Name": "PSet", "CustomerManagedPolicies": ["myPolicy"]}
        self.assertEqual(validate_customer_managed_policy_paths(template), [])

    def test_a_path_with_a_leading_slash_is_valid(self):
        template = {"Name": "PSet", "CustomerManagedPolicies": ["/sso/global/myPolicy"]}
        self.assertEqual(validate_customer_managed_policy_paths(template), [])

    def test_a_path_without_a_leading_slash_is_rejected(self):
        template = {"Name": "PSet", "CustomerManagedPolicies": ["sso/global/myPolicy"]}
        result = validate_customer_managed_policy_paths(template, source_file="p.json")
        self.assertEqual(len(result), 1)
        self.assertIn("p.json", result[0])
        # The message gives the corrected value
        self.assertIn("/sso/global/myPolicy", result[0])

    def test_an_arn_is_rejected(self):
        template = {
            "Name": "PSet",
            "CustomerManagedPolicies": [
                "arn:aws:iam::123456789012:policy/sso/myPolicy"
            ],
        }
        self.assertEqual(len(validate_customer_managed_policy_paths(template)), 1)

    def test_boundary_path_without_a_leading_slash_is_rejected(self):
        template = {
            "Name": "PSet",
            "CustomerPermissionBoundary": {"Path": "pbounds/", "Name": "PB"},
        }
        result = validate_customer_managed_policy_paths(template)
        self.assertEqual(len(result), 1)
        self.assertIn("/pbounds/", result[0])

    def test_boundary_path_with_a_leading_slash_is_valid(self):
        template = {
            "Name": "PSet",
            "CustomerPermissionBoundary": {"Path": "/pbounds/", "Name": "PB"},
        }
        self.assertEqual(validate_customer_managed_policy_paths(template), [])

    def test_boundary_without_a_path_is_valid(self):
        """The resolver uses "/" as the default value for a missing Path."""
        template = {"Name": "PSet", "CustomerPermissionBoundary": {"Name": "PB"}}
        self.assertEqual(validate_customer_managed_policy_paths(template), [])


class TestValidateAssignmentTargets(unittest.TestCase):

    def base_assignment(self, **overrides):
        assignment = {
            "PrincipalId": "SomeGroup",
            "PrincipalType": "GROUP",
            "PermissionSetName": "ViewOnlyAccess",
            "Target": ["111111111111"],
        }
        assignment.update(overrides)
        return assignment

    def test_valid_targets(self):
        assignment = self.base_assignment(
            Target=["111111111111", "ou-1234-12345678", "ROOT", "some-account-name"],
            Exclusions=["222222222222", "SandboxOU"],
        )
        self.assertEqual(validate_assignment_targets([assignment]), [])

    def test_an_unquoted_account_id_is_rejected(self):
        """
        YAML reads an unquoted account ID as a number and removes any leading zero.
        This is the defect that the shipped example file held.
        """
        result = validate_assignment_targets([self.base_assignment(Target=[11111111111])])
        self.assertEqual(len(result), 1)
        self.assertIn("Quote every account ID", result[0])

    def test_a_digit_string_of_the_wrong_length_is_rejected(self):
        for target in ["11111111111", "1234567890123"]:
            result = validate_assignment_targets(
                [self.base_assignment(Target=[target])]
            )
            self.assertEqual(len(result), 1, f"target {target}")
            self.assertIn("exactly 12 digits", result[0])

    def test_a_bad_exclusion_is_rejected(self):
        result = validate_assignment_targets(
            [self.base_assignment(Exclusions=[222222222222])]
        )
        self.assertEqual(len(result), 1)
        self.assertIn("Exclusions", result[0])

    def test_a_missing_or_empty_target_is_rejected(self):
        for assignment in [
            {"PrincipalId": "G", "PermissionSetName": "P"},
            self.base_assignment(Target=[]),
            self.base_assignment(Target="111111111111"),
        ]:
            result = validate_assignment_targets([assignment])
            self.assertEqual(len(result), 1, f"assignment {assignment}")
            self.assertIn("Target must be a list", result[0])


class TestValidateAssignments(unittest.TestCase):

    def test_reads_the_assignments_key(self):
        """
        An earlier version looped over assignment_templates.values(), which held one
        item: the list itself. That worked only because "Assignments" was the only key.
        """
        templates = {
            "Assignments": [
                {
                    "PrincipalId": "SomeGroup",
                    "PrincipalType": "GROUP",
                    "PermissionSetName": "ViewOnlyAccess",
                    "Target": ["111111111111"],
                }
            ],
            "SomeFutureKey": "ignored",
        }

        self.assertEqual(
            validate_assignments(templates, management_account_id="999999999999"), []
        )

    def test_a_malformed_target_gives_an_error_and_does_not_raise(self):
        """
        The other assignment checks read Target[0], so a malformed Target raised an
        IndexError or a KeyError instead of giving the user a message.
        """
        templates = {
            "Assignments": [{"PrincipalId": "G", "PermissionSetName": "P"}]
        }

        result = validate_assignments(templates, management_account_id="999999999999")

        self.assertEqual(len(result), 1)
        self.assertIn("Target must be a list", result[0])

    def test_a_control_tower_permission_set_is_rejected(self):
        templates = {
            "Assignments": [
                {
                    "PrincipalId": "SomeGroup",
                    "PrincipalType": "GROUP",
                    "PermissionSetName": "AWSAdministratorAccess",
                    "Target": ["111111111111"],
                }
            ]
        }

        result = validate_assignments(templates, management_account_id="999999999999")

        self.assertEqual(len(result), 1)
        self.assertIn("Control Tower", result[0])


class TestValidatePermissionSets(unittest.TestCase):

    @patch("boto3.client")
    def test_all_the_checks_run(self, mock_boto3_client):
        """
        Proves that the new checks are connected to validate_permission_sets, not only
        that they work when called directly.
        """
        mock_iam = MagicMock()
        mock_iam.get_policy.return_value = {"Policy": {}}
        mock_boto3_client.return_value = mock_iam
        templates = {
            "bad_name.json": {"Name": "my pset", "ManagedPolicies": []},
            "bad_path.json": {
                "Name": "GoodName",
                "CustomerManagedPolicies": ["sso/global/myPolicy"],
            },
            "duplicate.json": {"Name": "GoodName", "ManagedPolicies": []},
        }

        result = validate_permission_sets(templates, current_account_id="123456789012")

        joined = "\n".join(result)
        self.assertIn("Duplicate Permission Set Names", joined)
        self.assertIn("Terraform identifier", joined)
        self.assertIn("does not start with a slash", joined)


if __name__ == "__main__":
    unittest.main()
