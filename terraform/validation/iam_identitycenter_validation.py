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
import glob
import json
import argparse
import os
import logging
import re
import yaml
from .validate_policies import validate_policies
from .identifiers import (
    is_aws_account_id,
    is_valid_terraform_identifier,
    parse_customer_managed_policy_reference,
)
from collections import Counter
from typing import List
from botocore.exceptions import ClientError


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
    perm_set_dict = {}
    for each_file in os.listdir(permission_set_templates_path):
        if not each_file.endswith(".json"):
            continue
        with open(os.path.join(permission_set_templates_path, each_file)) as f:
            log.info(f"Loading permission set {each_file}")
            # Load the JSON file into a dictionary
            perm_set_dict[each_file] = json.load(f)
    log.info("Permission Sets successfully loaded from repository files")
    return perm_set_dict


def list_assignment_folder(assignment_templates_path):
    assig_dic = {"Assignments": []}
    assigments_file = glob.glob(assignment_templates_path + "/*.yaml")
    for each_file in assigments_file:
        with open(each_file) as f:
            assignments = yaml.safe_load(f)
        for each_assignment in assignments["Assignments"]:
            assig_dic["Assignments"].append(each_assignment)
    log.info("Assignments successfully loaded from repository files")
    return assig_dic


def validate_unique_permission_set_name(permission_set_templates):
    """
    Returns a list of errors, or an empty list if no errors found for this check.
    """
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
        return [f"ERROR - Duplicate Permission Set Names: {duplicates}"]

    log.info("No permission sets with the same name were detected.")
    return []


def validate_assignments_have_unique_identifiers(assignments_templates):
    """
    This function checks if the assignments have unique identifiers.
    Identifiers here refers to the combination of target, principal, and permission set
    If all 3 are the same, that indicates a duplicate that should be deduplicated.
    """
    duplicates = []
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
    else:
        log.info(
            "No asignment templates with the same identifiers were detected. Good!"
        )
    return duplicates


# Commented out because this is duplicative of the validate_policies.py helper script
# def validate_json_policy_format(permission_set_template):
#     """
#     Returns a list of errors
#     """
#     errors = []
#     client = boto3.client("accessanalyzer")
#     permission_set_object = json.dumps(permission_set_template)
#     permission_set_name = permission_set_object["Name"]

#     if "CustomPolicy" not in permission_set_object:
#         log.info(f"No inline policy present in permission set {permission_set_name}.")
#     else:
#         log.info(f"Analyzing inline policies for permission set {permission_set_name}.")
#         custom_policy = json.dumps(permission_set_template["CustomPolicy"])

#         # Get all findings from IAM Access Analyzer
#         all_findings = []
#         response = client.validate_policy(
#             locale="EN",
#             policyDocument=custom_policy,
#             policyType="IDENTITY_POLICY",
#         )
#         all_findings.extend(response["findings"])
#         next_token = response["NextToken"]
#         while next_token:
#             response = client.validate_policy(
#                 locale="EN",
#                 policyDocument=custom_policy,
#                 policyType="IDENTITY_POLICY",
#                 NextToken=response["NextToken"],
#             )
#             all_findings.extend(response["findings"])

#         # Loop over the findings and handle as appropriate
#         for each_finding in all_findings:
#             if each_finding["findingType"] == "ERROR":
#                 finding_string = (
#                     f"[{permission_set_name}] An error was found in the custom policy: "
#                     + str(each_finding["findingDetails"])
#                 )
#                 log.error(finding_string)
#                 errors.append(finding_string)

#             if each_finding["findingType"] == "WARNING":
#                 log.warning(
#                     f"[{permission_set_name}] A warning was found in the custom policy: "
#                     + str(each_finding["findingDetails"])
#                 )
#     return errors


# Client error codes that indicate a problem with the template, rather than a problem
# with the caller's permissions or with the service. These are reported as findings.
# Any other client error is re-raised: a validator that reports "policy not found"
# when it actually cannot read IAM would be worse than a crash.
TEMPLATE_ERROR_CODES = ("NoSuchEntity", "InvalidInput", "ValidationError")


def build_customer_policy_arn(account_id: str, path: str, policy_name: str) -> str:
    """
    Builds the ARN of a customer managed policy from its account, path and name.

    The path is normalised to start and end with a slash, because an IAM policy ARN
    always has exactly one slash between "policy" and the path.
    """
    normalised_path = str(path or "/").strip("/")
    if normalised_path:
        normalised_path = f"/{normalised_path}/"
    else:
        normalised_path = "/"
    return f"arn:aws:iam::{account_id}:policy{normalised_path}{policy_name}"


def validate_managed_policies_arn(permission_set_object, current_account_id):
    """
    Returns a list of errors in managed policies and permission boundaries.
    """
    errors = []
    permission_set_name = permission_set_object.get("Name", "<unnamed permission set>")

    client = boto3.client("iam")
    log.info(
        f"Analyzing the permission set managed policies for permission set {permission_set_name}."
    )
    # ManagedPolicies is optional: a permission set may instead use only
    # CustomerManagedPolicies or only CustomPolicy.
    for each_managed_policy in permission_set_object.get("ManagedPolicies", []):
        # The loop body handles its own errors so that one bad policy does not stop
        # the remaining policies from being checked.
        try:
            # This basically checks whether the managed policy exists
            _ = client.get_policy(PolicyArn=each_managed_policy)
        # Handle when resource is not found
        except ClientError as error:
            if error.response["Error"]["Code"] in TEMPLATE_ERROR_CODES:
                error_string = (
                    f"[{permission_set_name}] An issue was found in the managed policy "
                    f"'{each_managed_policy}'. Reason: " + str(error)
                )
                log.error(error_string)
                errors.append(error_string)
            else:
                # Unknown Client Error
                raise error

    log.info(
        f"[{permission_set_name}] Analyzing permission boundary policies from permission set"
    )
    customer_permission_boundary_object = permission_set_object.get(
        "CustomerPermissionBoundary", {}
    )
    if re.match(r"^arn:aws", customer_permission_boundary_object.get("Name", "")):
        error_string = f"[{permission_set_name}] You specified an permission boundary ARN instead of name. Please specify a name."
        log.error(error_string)
        errors.append(error_string)
    elif customer_permission_boundary_object:
        # Path is optional, and the resolver defaults a missing Path to "/".
        boundary_arn = build_customer_policy_arn(
            account_id=current_account_id,
            path=customer_permission_boundary_object.get("Path", "/"),
            policy_name=customer_permission_boundary_object["Name"],
        )
        try:
            _ = client.get_policy(PolicyArn=boundary_arn)
        except ClientError as error:
            if error.response["Error"]["Code"] in TEMPLATE_ERROR_CODES:
                error_string = (
                    f"[{permission_set_name}] An issue was found in the customer managed "
                    f"permission boundary policy '{boundary_arn}'. Reason: " + str(error)
                )
                log.error(error_string)
                errors.append(error_string)
            else:
                # Unknown Client Error
                raise error
    return errors


def validate_management_permission_sets_are_isolated(
    # An SSO account assignment object
    assignment_template,
    # The ID of the management account
    management_account_id,
    # The identifier used to identify management permission sets
    managementIdentifierRegex=r"MGMTACCT",
):
    """
    Returns a list of error messages for any mismatched permission sets that are assigned to the wrong class of account.

    If no mismatches, returns an empty list.

    Examples of mismatches:
    - Member account using a permission set named DataAccess_MGMTACCT
    - Management account using a permission set named DataAccess
    """
    invalid_assignments = []
    for assignment in assignment_template:
        account_target = assignment["Target"][0]
        is_mgmt_permisision_set = bool(
            re.search(managementIdentifierRegex, assignment["PermissionSetName"])
        )
        # A mismatch of permission sets and assignments is problematic and fail-worthy
        if (account_target == management_account_id) != is_mgmt_permisision_set:
            disposition_string = "is not the management account"
            if account_target == management_account_id:
                disposition_string = "is the management account"
            error_message = f"The permission set '{assignment['PermissionSetName']}' is assigned to the account '{account_target}', which {disposition_string}. Please review your template."
            log.error(error_message)
            invalid_assignments.append(error_message)
    return invalid_assignments


def validate_no_control_tower_psets_used_in_member_accounts(assignment_template):
    """
    Returns a list of all the given assignments that are using a Control Tower-managed permission set.

    Control Tower permission sets are not allowed in member accounts because they are also assigned in the management account.
    """
    errors = []
    control_tower_permission_set_names = [
        "AWSOrganizationsFullAccess",
        "AWSServiceCatalogEndUserAccess",
        "AWSServiceCatalogAdminFullAccess",
        "AWSPowerUserAccess",
        "AWSAdministratorAccess",
        "AWSReadOnlyAccess",
    ]
    for assignment in assignment_template:
        if assignment["PermissionSetName"] in control_tower_permission_set_names:
            error_message = f"The permission set '{assignment['PermissionSetName']}' is assigned in a member account. Control Tower permission sets are not allowed in member accounts. Please review your template."
            log.error(error_message)
            errors.append(error_message)
    return errors


def validate_permission_set_names_are_terraform_identifiers(
    permission_set_templates: dict,
) -> List[str]:
    """
    Returns a list of errors for any permission set Name that cannot be used as a
    Terraform identifier.

    The Name is written into six Terraform resource labels and references. A Name that
    Terraform does not accept produces a generated manifest that does not parse. That
    manifest is not committed to the repository, so the parse error names a file the
    reader cannot open. Reject the Name here instead.
    """
    errors = []
    for source_file, permission_set_template in permission_set_templates.items():
        permission_set_name = permission_set_template.get("Name", "")
        if not is_valid_terraform_identifier(permission_set_name):
            error_string = (
                f"ERROR - Permission set name '{permission_set_name}' in file "
                f"'{source_file}' cannot be used as a Terraform identifier. A name must "
                "start with a letter or an underscore, and can then contain only "
                "letters, digits, underscores and dashes."
            )
            log.error(error_string)
            errors.append(error_string)
    return errors


def validate_customer_managed_policy_paths(
    permission_set_template: dict,
    source_file: str = "",
) -> List[str]:
    """
    Returns a list of errors for any customer managed policy path that does not start
    with a slash.

    AWS requires a policy path to start with a slash. A value such as
    "sso/global/myPolicy" looks correct and is not, and AWS rejects it at apply time,
    which is after review and after merge. Reject it here instead.

    This also catches a policy ARN, which is not a supported value: the template must
    hold a policy name, optionally prefixed with its path.
    """
    errors = []
    permission_set_name = permission_set_template.get("Name", "<unnamed permission set>")
    location = f" in file '{source_file}'" if source_file else ""

    for policy_reference in permission_set_template.get("CustomerManagedPolicies", []):
        path, policy_base_name = parse_customer_managed_policy_reference(
            policy_reference
        )
        if not path.startswith("/"):
            error_string = (
                f"[{permission_set_name}] The customer managed policy "
                f"'{policy_reference}'{location} has the path '{path}', which does not "
                f"start with a slash. AWS rejects such a path at apply time. Use "
                f"'/{path}{policy_base_name}' instead."
            )
            log.error(error_string)
            errors.append(error_string)

    # An absent Path is valid: the resolver uses "/" as the default.
    boundary = permission_set_template.get("CustomerPermissionBoundary", {})
    boundary_path = boundary.get("Path")
    if boundary_path and not str(boundary_path).startswith("/"):
        error_string = (
            f"[{permission_set_name}] The CustomerPermissionBoundary path "
            f"'{boundary_path}'{location} does not start with a slash. AWS rejects such "
            f"a path at apply time. Use '/{boundary_path}' instead."
        )
        log.error(error_string)
        errors.append(error_string)

    return errors


def validate_assignment_targets(assignments: list) -> List[str]:
    """
    Returns a list of errors for any Target or Exclusions entry with the wrong shape.

    These checks are structural, so they run before the other assignment checks: those
    checks index Target[0] and would raise rather than return an error message.
    """
    errors = []
    for assignment in assignments:
        principal = assignment.get("PrincipalId", "<no PrincipalId>")
        permission_set = assignment.get("PermissionSetName", "<no PermissionSetName>")
        label = f"[{principal} / {permission_set}]"

        targets = assignment.get("Target")
        if not isinstance(targets, list) or not targets:
            error_string = (
                f"{label} Target must be a list with at least one entry. Every "
                "assignment needs a target."
            )
            log.error(error_string)
            errors.append(error_string)
            continue

        for key in ("Target", "Exclusions"):
            entries = assignment.get(key, [])
            if not isinstance(entries, list):
                error_string = f"{label} {key} must be a list."
                log.error(error_string)
                errors.append(error_string)
                continue
            for entry in entries:
                errors += validate_target_entry(entry, key=key, label=label)
    return errors


def validate_target_entry(entry, key: str, label: str) -> List[str]:
    """
    Returns a list of errors for a single Target or Exclusions entry.
    """
    # A bool is a subclass of int, so check it first.
    if isinstance(entry, bool):
        error_string = f"{label} {key} entry '{entry}' must be a string."
        log.error(error_string)
        return [error_string]

    if isinstance(entry, int):
        error_string = (
            f"{label} {key} entry {entry} was read as a number. Quote every account ID, "
            f"for example '{entry:012d}', or YAML removes a leading zero and the "
            "account cannot be found."
        )
        log.error(error_string)
        return [error_string]

    entry_text = str(entry)
    if entry_text.isdigit() and not is_aws_account_id(entry_text):
        error_string = (
            f"{label} {key} entry '{entry_text}' has {len(entry_text)} digits. An AWS "
            "account ID has exactly 12 digits."
        )
        log.error(error_string)
        return [error_string]

    return []


def validate_permission_sets(
    permission_set_templates: dict,
    current_account_id,
):
    errors = []
    errors += validate_unique_permission_set_name(permission_set_templates)
    errors += validate_permission_set_names_are_terraform_identifiers(
        permission_set_templates
    )
    for source_file, permission_set_template in permission_set_templates.items():
        # errors += validate_json_policy_format(permission_set_template)
        errors += validate_managed_policies_arn(
            permission_set_template,
            current_account_id=current_account_id,
        )
        errors += validate_customer_managed_policy_paths(
            permission_set_template,
            source_file=source_file,
        )
    return errors


def validate_assignments(
    assignment_templates: dict,
    management_account_id: str,
):
    # Read the Assignments list explicitly. An earlier version looped over
    # assignment_templates.values(), which held exactly one item: the list itself. That
    # worked only because "Assignments" is the only key.
    assignments = assignment_templates.get("Assignments", [])

    # Structural checks run first and stop the validation on failure. The checks below
    # index Target[0], so a malformed Target would raise an IndexError or a KeyError
    # instead of giving the user an error message.
    structural_errors = validate_assignment_targets(assignments)
    if structural_errors:
        return structural_errors

    errors = []
    errors += validate_assignments_have_unique_identifiers(assignment_templates)
    errors += validate_management_permission_sets_are_isolated(
        assignments, management_account_id=management_account_id
    )
    errors += validate_no_control_tower_psets_used_in_member_accounts(assignments)
    return errors


def main(
    permission_set_templates_path,
    assignment_templates_path,
    fail_on_types: List[str],
):
    """
    Returns True if all checks successfully passed validation.
    Otherwise, returns False.
    """
    print("########################################")
    print("# Starting AWS SSO Template Validation #")
    print("########################################\n")

    current_account_id = boto3.client("sts").get_caller_identity()["Account"]
    management_account_id = boto3.client("organizations").describe_organization()[
        "Organization"
    ]["MasterAccountId"]

    # These functions load the templates from the repository JSON/YAML files
    permission_set_templates = list_permission_set_folder(permission_set_templates_path)
    assignments_templates = list_assignment_folder(assignment_templates_path)

    # Permission Sets
    permission_set_errors = validate_permission_sets(
        permission_set_templates=permission_set_templates,
        current_account_id=current_account_id,
    )
    if permission_set_errors:
        log.error(
            "Permission sets failed validation. Review findings and correct them:"
        )
        for permission_set_error in permission_set_errors:
            log.error(permission_set_error)
        return False

    # Assignments
    assignment_errors = validate_assignments(
        assignment_templates=assignments_templates,
        management_account_id=management_account_id,
    )
    if assignment_errors:
        log.error("Assignments failed validation. Review findings and correct them:")
        if isinstance(assignment_errors, list):
            for assignment_error in assignment_errors:
                log.error(assignment_error)
        else:
            log.error(assignment_errors)
        return False

    # Policies
    # Pass the configured path through: validate_policies has its own default, so a
    # custom permission_set_templates_path previously matched no files at all and the
    # inline policy check silently passed.
    policy_errors = validate_policies(
        fail_on_types=fail_on_types,
        permission_sets_path_identifier=os.path.join(
            permission_set_templates_path, "*.json"
        ),
    )
    if policy_errors:
        log.error("Policies failed validation. Review findings and correct them:")
        # check if it's a list or string so we don't print out individual characters in a loop
        if isinstance(policy_errors, list):
            for policy_error in policy_errors:
                log.error(policy_error)
        else:
            log.error(policy_errors)
        return False

    log.info("Congrats! All templates were evaluated without errors! :)")
    return True


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
    parser.add_argument(
        "--fail-on-types",
        # nargs="+" keeps this a list. Without it, a supplied value is a string, and
        # the membership test in validate_policies becomes a substring test.
        nargs="+",
        default=["ERROR"],
        help="The types of policy findings that should cause the script to fail.",
    )
    args = parser.parse_args()
    permission_set_templates_path = args.psFolder
    assignment_templates_path = args.asFolder
    fail_on_types = args.fail_on_types
    main(
        permission_set_templates_path=permission_set_templates_path,
        assignment_templates_path=assignment_templates_path,
        fail_on_types=fail_on_types,
    )
