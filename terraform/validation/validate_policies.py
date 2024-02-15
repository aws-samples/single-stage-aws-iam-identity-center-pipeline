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


def validate_policies():
    """
    Returns true if all files pass validation. Otherwise, false.
    """
    bad_files = []
    access_analyzer_client = boto3.client("accessanalyzer")
    files = glob.glob("./source/permission_sets/templates/*.json")
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
                if (
                    finding["findingType"] == "SECURITY_WARNING"
                    or finding["findingType"] == "ERROR"
                ):
                    del finding[
                        "locations"
                    ]  # Remove overly verbose location information
                    filtered_findings.append(finding)
            if filtered_findings:
                bad_files += file
                logging.error(f"Failed policy validation for {file}. Details:")
                logging.error(filtered_findings)

    return len(bad_files) == 0
