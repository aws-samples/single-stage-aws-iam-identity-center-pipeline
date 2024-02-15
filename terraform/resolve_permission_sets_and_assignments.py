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

## + ----------------------------------
## | AWS SSO Assignments Management
## +-----------------------------------

"""
Summary
    This script will take directories of permission set and assignment JSON files and generate
    Terraform code that will deploy the permission sets and assignments.

    This script is intended to be run from a pipeline that is in line with Terraform plan/apply.
    You should not regularly run this script locally, nor should you commit its results to a code repo. Let the pipeline do the work.

Requirements
    This script requires read-only delegated administrator permissions in order to query the AWS Organizations service.
    The following permissions should be configured from the management account:
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowSSOAdminToQueryOrg",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::${sso_delegated_admin_account_id}:root"
      },
      "Action": [
        "organizations:ListAccounts",
        "organizations:DescribeOrganization",
        "organizations:DescribeOrganizationalUnit",
        "organizations:ListRoots",
        "organizations:ListAWSServiceAccessForOrganization",
        "organizations:ListDelegatedAdministrators"
      ],
      "Resource": "*"
    }
  ]
}

Inputs
    A path to a directory containing JSON files with IAM Identity Center Permission Set information
    A path to a directory containing JSON files with IAM Identity Center Assignment information
    A flag indicating whether assignments should be generated for the management account or for member accounts (default: member)

Outputs
    assignments_auto.tf: Terraform manifest that represents the assignments
    permission_sets_auto.tf: Terraform manifest that represents the permission sets
"""

import boto3
import glob
import json
import os
import logging
from botocore.config import Config
import re
import argparse
import validation.iam_identitycenter_validation as iam_identitycenter_validation

# Logging configuration
logging.basicConfig(
    format="%(asctime)s,%(msecs)03d %(levelname)-8s [%(filename)s:%(lineno)d] %(message)s",
    datefmt="%Y-%m-%d:%H:%M:%S",
    level=logging.DEBUG,
)
log = logging.getLogger()
log.setLevel(logging.INFO)


REGION = "us-east-2"
boto_config = Config(region_name=REGION)


def get_permission_set_resource(data: dict) -> str:
    """
    Helper function to generate the Terraform resource for a permission set.
    :param data: The JSON data for the permission set
    :return: A string containing the Terraform resource for the permission set.
    :rtype: str
    """
    return f"""
resource "aws_ssoadmin_permission_set" "{data["Name"]}" {{
  lifecycle {{
    ignore_changes = [
      instance_arn
    ]
  }}
  name             = "{data["Name"]}"
  description      = "{data["Description"]}"
  instance_arn     = local.sso_instance_arn
  session_duration = "{data["SessionDuration"]}"
}}
"""


def get_permission_set_managed_policies(data: dict):
    """
    Helper function to generate the Terraform resource for a permission set's attached managed policies.
    :param data: The JSON data for the permission set
    :return: A list of strings containing the Terraform resource for the permission set attached managed policies.
    :rtype: list[str]

    """
    attachment_strings = []
    for policy in data["ManagedPolicies"]:
        policy_name = policy.split("/")[-1]
        attachment_strings.append(
            f"""
resource "aws_ssoadmin_managed_policy_attachment" "{data["Name"]}_managed_policy_{policy_name}" {{
  lifecycle {{
    ignore_changes = [
      instance_arn
    ]
  }}
  instance_arn       = local.sso_instance_arn
  managed_policy_arn = "{policy}"
  permission_set_arn = aws_ssoadmin_permission_set.{data["Name"]}.arn
}}
"""
        )
    return attachment_strings


def get_permission_set_customer_managed_policies(data: dict):
    """
    Helper function to generate the Terraform resource for a permission set's attached customer managed policies.
    :param data: The JSON data for the permission set
    :return: A list of strings containing the Terraform resource for the permission set's attached customer managed policies.
    :rtype: list[str]
    """
    # TODO - Currently assumes that the path is root (/). Will fix in future version.
    attachment_strings = []
    for policy_name in data["CustomerManagedPolicies"]:
        attachment_strings.append(
            f"""
resource "aws_ssoadmin_customer_managed_policy_attachment" "{data["Name"]}_customer_managed_policy_{policy_name}" {{
  lifecycle {{
    ignore_changes = [
      instance_arn
    ]
  }}
  instance_arn       = local.sso_instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.{data["Name"]}.arn
  customer_managed_policy_reference {{
    name = "{policy_name}"
    path = "/"
  }}
}}
"""
        )
    return attachment_strings


def get_permission_set_custom_policy(data: dict, permission_set_file_path: str) -> str:
    """
    Helper function to generate the Terraform resource for a permission set's attached custom/inline policy
    :param data: The JSON data for the permission set
    :return: A string containing the Terraform resource for the permission set's attached custom/inline policy
    :rtype: str
    """
    escaped_permission_set_file_path = permission_set_file_path.replace("\\", "/")
    return f"""
resource "aws_ssoadmin_permission_set_inline_policy" "{data['Name']}_custom_policy" {{
  lifecycle {{
    ignore_changes = [
      instance_arn
    ]
  }}
  instance_arn       = local.sso_instance_arn
  inline_policy      = jsonencode(jsondecode(file("{escaped_permission_set_file_path}")).CustomPolicy)
  permission_set_arn = aws_ssoadmin_permission_set.{data['Name']}.arn
}}
"""


def get_permission_set_permission_boundary(data) -> str:
    """
    Helper function to generate the Terraform resource for a permission set's permission boundary
    :param data: The JSON data for the permission set
    :return: A string containing the Terraform resource for the permission set's permission boundary
    :rtype: str
    """
    # Validate data
    if "CustomerPermissionBoundary" in data and "AwsPermissionBoundaryArn" in data:
        logging.error(f"Error in permission set {data.get('Name','')}")
        raise Exception(
            "You cannot specify more than one permission boundary for a permission set."
        )

    # Customer permission boundary
    if "CustomerPermissionBoundary" in data:
        if "Path" in data["CustomerPermissionBoundary"]:
            path = data["CustomerPermissionBoundary"]["Path"]
        else:
            path = "/"
        permissions_boundary_payload = f"""customer_managed_policy_reference {{
      name = "{data['CustomerPermissionBoundary']['Name']}"
      path = "{path}"
    }}"""
    # AWS permission boundary
    elif "AwsPermissionBoundaryArn" in data:
        permissions_boundary_payload = (
            f"managed_policy_arn = \"{data['AwsPermissionBoundaryArn']}\""
        )

    # Put it all together
    return f"""
resource "aws_ssoadmin_permissions_boundary_attachment" "{data['Name']}_permission_boundary" {{
  lifecycle {{
    ignore_changes = [
      instance_arn
    ]
  }}

  instance_arn       = local.sso_instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.{data["Name"]}.arn
  permissions_boundary {{
    {permissions_boundary_payload}
  }}
}}
"""


def get_permission_set_manifest_content(template_path: str, mgmt_only: bool):
    """
    Takes a path to a directory containing permission set JSON files and returns the Terraform resources for the
    permission sets.
    :param template_path: The path to the directory containing permission set JSON files
    :param mgmt_only: Whether to include MGMTACCT files or not
    :return: A string containing the Terraform resource for the permission sets, intended to be written to a file
    :rtype: str
    """
    output = ""
    for eachFile in glob.glob(os.path.join(template_path, "*.json")):
        # Skip MGMTACCT files if we're not in MGMT_ONLY mode; skip non-MGMTACCT files if we're in MGMT_ONLY mode
        if bool(re.search(r"MGMTACCT", eachFile.upper())) != (mgmt_only):
            continue
        tf_resources_for_template = []
        with open(eachFile, "r") as convert_file:
            try:
                data = json.load(convert_file)
                tf_resources_for_template.append(get_permission_set_resource(data))
                if "ManagedPolicies" in data:
                    tf_resources_for_template += get_permission_set_managed_policies(
                        data
                    )
                if "CustomerManagedPolicies" in data:
                    tf_resources_for_template += (
                        get_permission_set_customer_managed_policies(data)
                    )
                if "CustomPolicy" in data:
                    tf_resources_for_template.append(
                        get_permission_set_custom_policy(
                            data, permission_set_file_path=eachFile
                        )
                    )
                if (
                    "AwsPermissionBoundaryArn" in data
                    and bool(data["AwsPermissionBoundaryArn"])
                ) or (
                    "CustomerPermissionBoundary" in data
                    and bool(data["CustomerPermissionBoundary"])
                ):
                    tf_resources_for_template.append(
                        get_permission_set_permission_boundary(data)
                    )
                output += "\n".join(tf_resources_for_template)
            except Exception as e:
                logging.error(repr(e))
                raise Exception(
                    f"Error parsing file {eachFile}. Review its contents to make sure it is valid."
                )
    return output


def load_assignments_from_file(template_path: str):
    """ """
    assigments_files = glob.glob(os.path.join(template_path, "*.json"))
    if not assigments_files:
        raise Exception(f"No assignments files found in directory {template_path}")
    assign_dic = {}
    assignments_list = []

    for eachFile in assigments_files:
        with open(eachFile, "r") as convert_file:
            data = json.load(convert_file)
            assignments_list.extend(data["Assignments"])
    assign_dic["Assignments"] = assignments_list
    log.info("Assignments successfully loaded from repository files")
    return assign_dic


def resolve_ou_names(ou_id: str, client):
    """
    Recursively resolves OU names to a list of all child account names for that OU.
    Used to help resolve OU names to OU IDs.
    """
    response = client.list_organizational_units_for_parent(ParentId=ou_id)
    results = response["OrganizationalUnits"]
    while "NextToken" in response:
        response = client.list_organizational_units_for_parent(
            ParentId=ou_id, NextToken=response["NextToken"]
        )
        results.extend(response["OrganizationalUnits"])

    if results:
        for each_ou in results:
            results.extend(resolve_ou_names(each_ou["Id"], client))

    return results


def list_accounts_in_ou(ou_identifier: str):
    """
    Given an OU identifier (which can be an OU ID, OU name, root ID, or literal 'ROOT'), returns a list of all accounts in that OU/root.
    Account names CANNOT be used as identifiers.

    Root will include ALL accounts in the organization (except the management account)
    OU names/IDs will NOT be recursively walked; only the direct child accounts of the OU will be included
    """
    client = boto3.client("organizations", config=boto_config)
    try:
        # Case for OU ID
        if "ou-" in ou_identifier:
            response = client.list_accounts_for_parent(ParentId=ou_identifier)
            results = response["Accounts"]
            while "NextToken" in response:
                response = client.list_accounts_for_parent(
                    ParentId=ou_identifier, NextToken=response["NextToken"]
                )
                results.extend(response["Accounts"])
        # Case for Root
        elif "r-" in ou_identifier or "ROOT" == ou_identifier.upper():
            response = client.list_accounts()
            results = response["Accounts"]
            while "NextToken" in response:
                response = client.list_accounts(NextToken=response["NextToken"])
                results.extend(response["Accounts"])
        # Case for OU Name (not ID)
        else:
            # Get all OU names and walk through them until we find the OU name in question
            root_id = client.list_roots()["Roots"][0]["Id"]
            log.info(f"Attempting to resolve OU Name {ou_identifier} to an OU ID")
            results = resolve_ou_names(ou_id=root_id, client=client)
            ou_ids_from_name = []
            for each_ou in results:
                if each_ou["Name"] == ou_identifier:
                    ou_ids_from_name.append(each_ou["Id"])
                    log.info(
                        f"[OU: {ou_identifier}] Organization Unit ID found for OU name"
                    )
            if len(ou_ids_from_name) != 1:
                raise Exception(
                    f"Did not find a unique, exact name match. Expected 1 result for {ou_identifier}, but got {ou_ids_from_name}"
                )
            else:
                ou_id_from_name = ou_ids_from_name[0]
            # Get all accounts in the OU
            response = client.list_accounts_for_parent(ParentId=ou_id_from_name)
            results = response["Accounts"]
            while "NextToken" in response:
                response = client.list_accounts_for_parent(
                    ParentId=ou_identifier, NextToken=response["NextToken"]
                )
                results.extend(response["Accounts"])

    except Exception as error:
        log.error(
            "It was not possible to list accounts from Organization Unit. Reason: "
            + repr(error)
        )

    # Filter out any inactive accounts
    account_list = []
    for eachResult in results:
        if eachResult["Status"] == "ACTIVE":
            account_list.append(eachResult["Id"])
    return account_list


def lookup_principal_id(
    principalName: str, principalType: str, identity_store_id: str
) -> str:
    """
    Given an identity store and principal Name and Type, looks up the user ID in the given Identity Store
    Returns: string with User ID
    """
    try:
        client = boto3.client("identitystore", config=boto_config)
        if principalType == "GROUP":
            response = client.list_groups(
                IdentityStoreId=identity_store_id,
                Filters=[
                    {"AttributePath": "DisplayName", "AttributeValue": principalName},
                ],
            )
            return response["Groups"][0]["GroupId"]
        if principalType == "USER":
            response = client.list_users(
                IdentityStoreId=identity_store_id,
                Filters=[
                    {"AttributePath": "UserName", "AttributeValue": principalName},
                ],
            )
            return response["Users"][0]["UserId"]
    except Exception as error:
        log.error(
            f"[PR: {principalName}] [{principalType}]  It was not possible lookup target. Reason: "
            + repr(error)
        )


def create_permission_set_arn_dict(instance_id: str):
    """
    Given an SSO instance_id, returns a dict mapping Permission Set names to ARNs for all permission sets in that SSO instance.
    """
    sso_client = boto3.client("sso-admin", config=boto_config)
    log.info("Creating permission set ARN dictionary")
    permission_set_arn_dict = {}
    for each_assignment in sso_client.list_permission_sets(
        InstanceArn=instance_id, MaxResults=100
    )["PermissionSets"]:
        permission_set_name = sso_client.describe_permission_set(
            PermissionSetArn=each_assignment, InstanceArn=instance_id
        )["PermissionSet"]["Name"]
        if permission_set_name in permission_set_arn_dict:
            raise Exception(
                "Duplicate permission set name detected. This is not allowed. Please check the manifest file for permission sets and fix the issue"
            )
        permission_set_arn_dict[permission_set_name] = each_assignment
    return permission_set_arn_dict


def resolve_targets(each_current_assignments: dict) -> list:
    """
    Given an assignment JSON object, loop through its targets and flatten any OU/root references to the child accounts of that OU/root.

    Only the direct child accounts of an OU will be included in the resolved list; sub-OUs' accounts will not be included.
    If root is specified, however, all accounts in the Organization (except the management account) will be included.
    """
    try:
        account_list = []
        identifier_string = f"{each_current_assignments['Target']}|{each_current_assignments['PrincipalId']}|{each_current_assignments['PermissionSetName']}"
        log.info(f"[Identifier: {identifier_string}] Resolving target in accounts")
        for eachTarget in each_current_assignments["Target"]:
            pattern = re.compile(r"\d{12}")  # Regex for AWS Account Id
            if pattern.match(eachTarget):
                account_list.append(eachTarget)
            else:
                account_list.extend(list_accounts_in_ou(ou_identifier=eachTarget))
        return account_list
    except Exception as error:
        log.error(
            f"[Identifier: {identifier_string}] It was not possible to resolve the targets from assignment. Reason: "
            + repr(error)
        )


def get_assignments_manifest(
    account: str,
    assignment: dict,
    principal_numeric_id: str,
    permission_set_arn_dict: dict,
) -> str:
    """
    Helper function to create a Terraform manifest for each assignment from the provided inputs
    """
    pattern = r"[^a-zA-Z0-9-_]"
    escaped_principal = re.sub(pattern, "", assignment["PrincipalId"])
    # If managed by Control Tower, just specify the ARN directly, otherwise reference our permission set
    if assignment["PermissionSetName"] in CONTROL_TOWER_PERMISSION_SETS:
        permission_set_arn = permission_set_arn_dict[assignment["PermissionSetName"]]
        permission_set_argument = f'"{permission_set_arn}"'
    else:
        permission_set_argument = (
            f"aws_ssoadmin_permission_set.{assignment['PermissionSetName']}.arn"
        )
    return f"""
resource "aws_ssoadmin_account_assignment" "assignment_{account}{escaped_principal}{assignment['PrincipalType']}{assignment['PermissionSetName']}" {{
  instance_arn       = local.sso_instance_arn
  permission_set_arn = {permission_set_argument}
  principal_id       = "{principal_numeric_id}"
  principal_type     = "{assignment['PrincipalType']}"
  target_id          = "{account}"
  target_type        = "AWS_ACCOUNT"
}}
"""


def create_assignments_manifest_from_repo_assignments(
    repository_assignments: dict, identity_store: str, permission_set_name_dict: dict
) -> dict:
    """
    Returns a string containing a Terraform manifest with all assignments represented by the template files.
    """
    log.info("Creating assignment dictionary with resolved account names")
    output_assignments_manifest = []
    org_client = boto3.client("organizations", config=boto_config)
    management_account = org_client.describe_organization()["Organization"][
        "MasterAccountId"
    ]

    resolved_assignments = {}
    resolved_assignments["Assignments"] = []
    try:
        for assignment in repository_assignments["Assignments"]:
            accounts = resolve_targets(assignment)
            principal_numeric_id = lookup_principal_id(
                assignment["PrincipalId"],
                assignment["PrincipalType"],
                identity_store_id=identity_store,
            )

            for eachAccount in accounts:
                # This is just fancy XOR logic
                # If the account is the management account and the assignment flag is for management only,
                # then we will add the assignment to the resolved_assignments dictionary.
                # Otherwise, we will skip it.
                # If the account is not the management account and the assignment flag is NOT management only,
                # then we will add the assignment to the resolved_assignments dictionary.
                if (eachAccount == management_account) == (mgmt_only):
                    # resolved_assignments["Assignments"].append(
                    #     {
                    #         "Sid": str(eachAccount)
                    #         + str(assignment["PrincipalId"])
                    #         + str(assignment["PrincipalType"])
                    #         + str(assignment["PermissionSetName"]),
                    #         "PrincipalId": principal_numeric_id,
                    #         "PrincipalType": assignment["PrincipalType"],
                    #         "PermissionSetArn": permission_set_name_dict[
                    #             assignment["PermissionSetName"]
                    #         ],
                    #         "Target": eachAccount,
                    #     }
                    # )
                    output_assignments_manifest.append(
                        get_assignments_manifest(
                            account=eachAccount,
                            assignment=assignment,
                            principal_numeric_id=principal_numeric_id,
                            permission_set_arn_dict=permission_set_name_dict,
                        )
                    )

        output_assignments_manifest = "\n".join(output_assignments_manifest)
        return output_assignments_manifest
    except Exception as error:
        log.error("Error: " + repr(error))
        exit(1)


# def resolve_control_tower_permission_set_arns(permission_set_names):
#     all_permission_sets = []
#     return_value = {}


if __name__ == "__main__":
    # Environment variable that determines whether to generate management or member assignments
    try:
        mgmt_only_env = os.environ.get("MGMT_ONLY").lower() in ["true", "1"]
    except AttributeError:
        logging.warning("Environment variable MGMT_ONLY not set, assuming False")
        mgmt_only_env = False

    # Setting arguments
    parser = argparse.ArgumentParser(description="AWS SSO Permission Set Management")
    parser.add_argument(
        "--templates-relative-path",
        action="store",
        help="Relative path (from this script) of the directory containing the input assignment JSON files",
        default="./source/assignments/templates",
    )
    parser.add_argument(
        "--permission-sets-template-relative-path",
        action="store",
        help="Relative path (from this script) of the directory containing the input permission set JSON files",
        default="./source/permission_sets/templates",
    )
    parser.add_argument(
        "--mgmt-only",
        action="store",
        type=bool,
        help="Flag to indicate whether to generate management or member assignments. This will override the environment variable MGMT_ONLY, if specified",
        default=False,
    )

    args = parser.parse_args()
    templates_relative_path = args.templates_relative_path
    permission_sets_template_relative_path = args.permission_sets_template_relative_path
    mgmt_only = args.mgmt_only
    if mgmt_only is None:
        mgmt_only = mgmt_only_env
    PERMISSION_SET_MANIFEST_OUTPUT_FILE_PATH = "./permission_sets_auto.tf"
    ASSIGNMENTS_MANIFEST_OUTPUT_FILE_PATH = "./assignments_auto.tf"
    CONTROL_TOWER_PERMISSION_SETS = [
        "AWSOrganizationsFullAccess",
        "AWSServiceCatalogEndUserAccess",
        "AWSServiceCatalogAdminFullAccess",
        "AWSPowerUserAccess",
        "AWSAdministratorAccess",
        "AWSReadOnlyAccess",
    ]
    # CONTROL_TOWER_PERMISSION_SETS_TO_ARNS = resolve_control_tower_permission_set_arns(
    #     CONTROL_TOWER_PERMISSION_SETS
    # )

    print("#######################################")
    print("# Starting AWS SSO Validation Section #")
    print("#######################################\n")
    iam_identitycenter_validation.main(
        permission_set_templates_path=permission_sets_template_relative_path,
        assignment_templates_path=templates_relative_path,
    )

    print("#######################################")
    print("# Starting AWS SSO Resolution Section #")
    print("#######################################\n")
    # Config to handle throttling
    config = Config(
        retries={"max_attempts": 1000, "mode": "adaptive"},
        region_name=REGION,
    )

    # Get Identity Store and SSO Instance ARN
    sso_client = boto3.client("sso-admin", config=config)
    response = sso_client.list_instances()
    sso_instance_arn = response["Instances"][0]["InstanceArn"]
    identity_store = response["Instances"][0]["IdentityStoreId"]

    # Create Permission Set Manifest
    permission_set_manifest_content = get_permission_set_manifest_content(
        template_path=permission_sets_template_relative_path, mgmt_only=mgmt_only
    )
    with open(PERMISSION_SET_MANIFEST_OUTPUT_FILE_PATH, "w") as f:
        f.write(permission_set_manifest_content)
        log.info("Permission Set Manifest successfully created.")

    # Create Assignment Manifest from repo contents
    repository_assignments = load_assignments_from_file(
        template_path=templates_relative_path
    )
    # Create permission set dictionary to help resolve permission set names/IDs
    permission_set_name_dict = create_permission_set_arn_dict(
        instance_id=sso_instance_arn
    )

    # Get assignments for individual accounts and the
    output_assignments_manifest = create_assignments_manifest_from_repo_assignments(
        repository_assignments=repository_assignments,
        identity_store=identity_store,
        permission_set_name_dict=permission_set_name_dict,
    )

    with open(ASSIGNMENTS_MANIFEST_OUTPUT_FILE_PATH, "w") as f:
        f.write(output_assignments_manifest)
        logging.info(output_assignments_manifest)  # So we can see the output

    log.info("Association file successfully created.")
