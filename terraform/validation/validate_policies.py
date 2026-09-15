"""
This script will validate the inline policies defined for permission sets in the repository.

It will NOT check for overly-permissive *managed* policies.
For example, if AdministratorAccess is attached to a permission set,
this script will NOT flag it as problematic (though it likely is).
"""

import boto3
import glob
import json
import logging


def validate_policies(
    fail_on_types=["ERROR"],
    permission_sets_path_identifier: str = "./source/permission_sets/templates/*.json",
):
    """
    Returns a list of files that failed policy validation, or an empty list if all files passed.

    :param fail_on_types: A list of IAM Access Analyzer finding types that should fail
        validation. This must be a list, not a string: a string would make the
        membership test below a substring test, so a WARNING finding would match a
        fail_on_types of "SECURITY_WARNING".
    :param permission_sets_path_identifier: A glob matching the permission set files.
    """
    bad_files = []
    access_analyzer_client = boto3.client("accessanalyzer")
    files = [
        f for f in glob.glob(permission_sets_path_identifier) if f.endswith(".json")
    ]
    for file in files:
        with open(file, "r") as f:
            policy_raw = f.read()
            policy_json = json.loads(policy_raw)
            inline_policy = policy_json.get("CustomPolicy", {})
            if not inline_policy:
                logging.info(f"No inline policy detected for {file}")
                continue
            logging.info(f"Validating inline policy for {file}")
            findings = access_analyzer_client.validate_policy(
                policyDocument=json.dumps(inline_policy),
                policyType="IDENTITY_POLICY",
            )["findings"]
            filtered_findings = []
            for finding in findings:
                if finding["findingType"] in fail_on_types:
                    del finding[
                        "locations"
                    ]  # Remove overly verbose location information
                    filtered_findings.append(finding)
            if filtered_findings:
                bad_files.append(file)
                logging.error(f"Failed policy validation for {file}. Details:")
                logging.error(filtered_findings)

    return bad_files
