# Unit Tests for validation/validate_policies.py

# Required mocks
# accessanalyzer: validate_policy

import json
import unittest
from pyfakefs import fake_filesystem_unittest
from unittest.mock import patch, MagicMock
from validation.validate_policies import validate_policies

PERMISSION_SET_WITH_INLINE_POLICY = {
    "Name": "HasInlinePolicy",
    "Description": "A permission set with an inline policy",
    "SessionDuration": "PT12H",
    "CustomPolicy": {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "GetRoleExample",
                "Action": ["iam:GetRole"],
                "Effect": "Allow",
                "Resource": "*",
            }
        ],
    },
}

PERMISSION_SET_WITHOUT_INLINE_POLICY = {
    "Name": "NoInlinePolicy",
    "Description": "A permission set with no inline policy",
    "SessionDuration": "PT12H",
    "ManagedPolicies": ["arn:aws:iam::aws:policy/job-function/ViewOnlyAccess"],
}


class TestValidatePolicies(fake_filesystem_unittest.TestCase):
    def setUp(self):
        self.setUpPyfakefs()
        self.template_path = "/custom/permission_sets/"
        self.fs.create_file(
            self.template_path + "has_inline_policy.json",
            contents=json.dumps(PERMISSION_SET_WITH_INLINE_POLICY),
        )
        self.fs.create_file(
            self.template_path + "no_inline_policy.json",
            contents=json.dumps(PERMISSION_SET_WITHOUT_INLINE_POLICY),
        )

    @patch("boto3.client")
    def test_uses_the_supplied_path(self, mock_boto3_client):
        """
        Only the file that holds an inline policy is submitted to Access Analyzer, and
        the supplied glob is what selects the files.
        """
        mock_analyzer = MagicMock()
        mock_analyzer.validate_policy.return_value = {"findings": []}
        mock_boto3_client.return_value = mock_analyzer

        result = validate_policies(
            fail_on_types=["ERROR"],
            permission_sets_path_identifier=self.template_path + "*.json",
        )

        self.assertEqual(result, [])
        mock_analyzer.validate_policy.assert_called_once_with(
            policyDocument=json.dumps(PERMISSION_SET_WITH_INLINE_POLICY["CustomPolicy"]),
            policyType="IDENTITY_POLICY",
        )

    @patch("boto3.client")
    def test_a_path_that_matches_no_files_checks_nothing(self, mock_boto3_client):
        """
        This is the behaviour that made the defect silent: the caller did not pass its
        configured path, so the default glob matched no files and every run passed.
        """
        mock_analyzer = MagicMock()
        mock_boto3_client.return_value = mock_analyzer

        result = validate_policies(
            fail_on_types=["ERROR"],
            permission_sets_path_identifier="/no/such/directory/*.json",
        )

        self.assertEqual(result, [])
        mock_analyzer.validate_policy.assert_not_called()

    @patch("boto3.client")
    def test_reports_a_file_with_a_failing_finding(self, mock_boto3_client):
        mock_analyzer = MagicMock()
        mock_analyzer.validate_policy.return_value = {
            "findings": [
                {
                    "findingType": "ERROR",
                    "findingDetails": "Something is wrong",
                    "locations": [],
                }
            ]
        }
        mock_boto3_client.return_value = mock_analyzer

        result = validate_policies(
            fail_on_types=["ERROR"],
            permission_sets_path_identifier=self.template_path + "*.json",
        )

        self.assertEqual(result, [self.template_path + "has_inline_policy.json"])

    @patch("boto3.client")
    def test_fail_on_types_must_be_a_list_not_a_string(self, mock_boto3_client):
        """
        A string makes the membership test a substring test, so a WARNING finding
        would match a fail_on_types of "SECURITY_WARNING". Passing a list keeps the
        comparison exact.
        """
        mock_analyzer = MagicMock()
        mock_analyzer.validate_policy.return_value = {
            "findings": [
                {
                    "findingType": "WARNING",
                    "findingDetails": "Just a warning",
                    "locations": [],
                }
            ]
        }
        mock_boto3_client.return_value = mock_analyzer

        result = validate_policies(
            fail_on_types=["SECURITY_WARNING", "ERROR"],
            permission_sets_path_identifier=self.template_path + "*.json",
        )

        self.assertEqual(result, [])


if __name__ == "__main__":
    unittest.main()
