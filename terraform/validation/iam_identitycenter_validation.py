# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.

# Permission is hereby granted, free of charge, to any person obtaining a copy of this
# software and associated documentation files (the "Software"), to deal in the Software
# without restriction, including without limitation the rights to use, copy, modify,
# merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
# INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
# PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
# HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
# SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

## + -----------------------
## | AWS SSO Templates Validation
## +-----------------------------------

import boto3
import botocore
import glob
import json
import argparse
import sys
import os
import logging
import re
import validation.validate_policies as validate_policies
from collections import Counter

"""
Arguments used by the script if invoked directory
--as-folder: Assignments folder. It can be found at AWS SSO > Settings > ARN
--ps-folder: Folder where the permission set files are. Default: '../templates/assignments/'
"""

# Logging configuration
logging.basicConfig(
    format="%(asctime)s,%(msecs)03d %(levelname)-8s [%(filename)s:%(lineno)d] %(message)s",
    datefmt="%Y-%m-%d:%H:%M:%S",
    level=logging.DEBUG,
)
log = logging.getLogger()
log.setLevel(logging.INFO)


def list_permission_set_folder(permission_set_templates_path):
    perm_set_dict = {
        eachFile: json.loads(
            open(os.path.join(permission_set_templates_path, eachFile)).read()
        )
        for eachFile in os.listdir(permission_set_templates_path)
    }
    log.info("Permission Sets successfully loaded from repository files")
    return perm_set_dict


def list_assignment_folder(assignment_templates_path):
    assigments_file = glob.glob(assignment_templates_path + "/*.json")
    assig_dic = {
        "Assignments": [
            assignment
            for eachFile in assigments_file
            for assignment in json.loads(open(eachFile).read())["Assignments"]
        ]
    }
    log.info("Assignments successfully loaded from repository files")
    return assig_dic


def validate_unique_permissionset_name(permission_set_templates):
    list_of_permission_set_name = []
    for permissionSet in permission_set_templates:
        try:
            list_of_permission_set_name.append(
                permission_set_templates[permissionSet]["Name"]
            )
        except KeyError:
            raise Exception(
                f"A required key was not found for permissionSet '{permissionSet}'. Review its contents and try again."
            )

    if len(list_of_permission_set_name) > len(set(list_of_permission_set_name)):
        log.error(
            "There are Permission Set templates with the same name. Please check your templates."
        )
        counter = Counter(list_of_permission_set_name)
        duplicates = [item for item, count in counter.items() if count > 1]
        log.error(f"Duplicate Permission Set Names: {duplicates}")
        exit(1)

    log.info("No permission sets with the same name were detected.")
    return True


def validate_unique_assignment_identifiers(assignments_templates):
    """
    Identifiers here refers to the combination of target, principal, and permission set
    If all 3 are the same, that indicates some sort of issue.
    """
    list_of_identifiers = []
    for eachAssignment in assignments_templates["Assignments"]:
        identifier_string = f"{eachAssignment['Target']}|{eachAssignment['PrincipalId']}|{eachAssignment['PermissionSetName']}"
        list_of_identifiers.append(identifier_string)

    if len(list_of_identifiers) > len(set(list_of_identifiers)):
        log.error(
            "There are Assignment templates with the same set of identifiers. Please check your templates."
        )
        counter = Counter(list_of_identifiers)
        duplicates = [item for item, count in counter.items() if count > 1]
        log.error(f"Duplicate Identifiers: {duplicates}")
        exit(1)
    log.info("No asignment templates with the same identifiers were detected.")
    return True


def validate_json_policy_format(permission_set_templates):
    log.info("Analyzing each one of the permission set custom policies.")
    client = boto3.client("accessanalyzer")

    for eachPermissionSet in permission_set_templates:
        if "CustomPolicy" in json.dumps(permission_set_templates[eachPermissionSet]):
            thereIsCustomPolicy = json.dumps(
                permission_set_templates[eachPermissionSet]["CustomPolicy"]
            )
            if len(thereIsCustomPolicy) > 2:
                log.info(f"[{eachPermissionSet}] Analyzing custom policy")
                response = client.validate_policy(
                    locale="EN",
                    policyDocument=json.dumps(
                        permission_set_templates[eachPermissionSet]["CustomPolicy"]
                    ),
                    policyType="IDENTITY_POLICY",
                )
                results = response["findings"]

                while "NextToken" in response:
                    response = client.validate_policy(
                        locale="PT_BR",
                        policyDocument=json.dumps(
                            permission_set_templates[eachPermissionSet]["CustomPolicy"]
                        ),
                        policyType="IDENTITY_POLICY",
                        NextToken=response["NextToken"],
                    )
                    results.extend(response["findings"])

                for eachFinding in results:
                    if eachFinding["findingType"] == "ERROR":
                        log.error(
                            f"[{eachPermissionSet}] An error was found in the custom policy: "
                            + str(eachFinding["findingDetails"])
                        )
                        exit(1)
                    if eachFinding["findingType"] == "WARNING":
                        log.warning(
                            f"[{eachPermissionSet}] An issue was found in the custom policy: "
                            + str(eachFinding["findingDetails"])
                        )
            else:
                log.info(
                    f"[{eachPermissionSet}] There is no Custom Policy in the permission set. Skipping"
                )


def validate_managed_policies_arn(permission_set_templates):
    log.info("Analyzing each one of the permission set managed policies.")
    client = boto3.client("iam")
    for eachPermissionSet in permission_set_templates:
        log.info(
            f"[{eachPermissionSet}] Analyzing AWS managed policies from permission set"
        )

        try:
            for eachManagedPolicy in permission_set_templates[eachPermissionSet][
                "ManagedPolicies"
            ]:
                response = client.get_policy(PolicyArn=eachManagedPolicy)
        except Exception as error:
            log.error(
                f"[{eachPermissionSet}] An issue was found in the managed policy. Reason: "
                + str(error)
            )
            exit(1)

    for eachPermissionSet in permission_set_templates:
        log.info(
            f"[{eachPermissionSet}] Analyzing permission boundary policies from permission set"
        )

        try:
            if (
                "PermissionBoundary" in permission_set_templates[eachPermissionSet]
            ) and (permission_set_templates[eachPermissionSet]["PermissionBoundary"]):
                if (
                    permission_set_templates[eachPermissionSet]["PermissionBoundary"][
                        "PolicyType"
                    ]
                    == "AWS"
                ):
                    response = client.get_policy(
                        PolicyArn=permission_set_templates[eachPermissionSet][
                            "PermissionBoundary"
                        ]["Policy"]
                    )
                else:
                    if (
                        "arn:aws"
                        in permission_set_templates[eachPermissionSet][
                            "PermissionBoundary"
                        ]["Policy"]
                    ):
                        log.error(
                            f"[{eachPermissionSet}] Looks like you are using an AWS ARN instead of the name of the policy you want as Permission Boundary. Please review your template"
                        )
                        exit(1)
        except Exception as error:
            log.error(
                f"[{eachPermissionSet}] An issue was found in the AWS managed permission boundary policy. Reason: "
                + str(error)
            )
            exit(1)


def validate_management_permission_set_isolation(
    assignmentsTemplates, managementIdentifierRegex=r"MGMTACCT"
):
    # Check if management permission sets are assigned to non-management accounts and vice-versa
    management_account_id = boto3.client("organizations").describe_organization()[
        "Organization"
    ]["MasterAccountId"]
    for eachAssignment in assignmentsTemplates["Assignments"]:
        account_target = eachAssignment["Target"][0]
        is_mgmt_permisision_set = bool(
            re.search(managementIdentifierRegex, eachAssignment["PermissionSetName"])
        )
        # A mismatch of permission sets and assignments indicates a problematic, fail-worthy build
        if (account_target == management_account_id) != is_mgmt_permisision_set:
            disposition_string = "is not the management account"
            if account_target == management_account_id:
                disposition_string = "is the management account"
            log.error(
                f"The permission set '{eachAssignment['PermissionSetName']}' is assigned to the account '{account_target}', which {disposition_string}. Please review your template."
            )
            exit(1)


def main(permission_set_templates_path, assignment_templates_path):
    print("########################################")
    print("# Starting AWS SSO Template Validation #")
    print("########################################\n")

    permission_set_templates = list_permission_set_folder(permission_set_templates_path)
    assignments_templates = list_assignment_folder(assignment_templates_path)

    # List of controls that will be validated
    validate_unique_permissionset_name(permission_set_templates)
    validate_unique_assignment_identifiers(assignments_templates)
    validate_json_policy_format(permission_set_templates)
    validate_managed_policies_arn(permission_set_templates)
    validate_management_permission_set_isolation(assignments_templates)
    if validate_policies.validate_policies() == False:
        log.error("Policies failed validation. Review findings and correct them.")
        exit(1)

    log.info("Congrats! All templates were evaluated without errors! :)")


if __name__ == "__main__":
    # Setting arguments
    parser = argparse.ArgumentParser(description="AWS SSO Assignment Management")
    parser.add_argument(
        "--ps-folder",
        action="store",
        dest="psFolder",
        default="./permission_sets/templates",
    )
    parser.add_argument(
        "--assignments-folder",
        action="store",
        dest="asFolder",
        default="./assignments/templates",
    )
    args = parser.parse_args()
    permission_set_templates_path = args.psFolder
    assignment_templates_path = args.asFolder
    main(
        permission_set_templates_path=permission_set_templates_path,
        assignment_templates_path=assignment_templates_path,
    )
