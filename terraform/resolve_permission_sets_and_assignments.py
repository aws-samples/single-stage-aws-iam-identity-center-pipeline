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
    This script will take directories of permission set and assignment files and generate
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
    A path to a directory containing files with IAM Identity Center Permission Set information
    A path to a directory containing files with IAM Identity Center Assignment information
    A flag indicating whether assignments should be generated for the management account or for member accounts (default: member)

Outputs
    assignments_auto.tf: Terraform manifest that represents the assignments
    permission_sets_auto.tf: Terraform manifest that represents the permission sets
"""

import argparse
import boto3
import glob
import json
import os
import logging
from botocore.config import Config
import re
import yaml
import argparse
import validation.iam_identitycenter_validation as iam_identitycenter_validation
from validation.identifiers import (
    is_aws_account_id,
    is_organization_root_id,
    is_organizational_unit_id,
    parse_customer_managed_policy_reference,
)
import sys

# Logging configuration
logging.basicConfig(
    format="%(asctime)s,%(msecs)03d %(levelname)-8s [%(filename)s:%(lineno)d] %(message)s",
    datefmt="%Y-%m-%d:%H:%M:%S",
    level=logging.DEBUG,
)
log = logging.getLogger()
log.setLevel(logging.INFO)


def get_permission_set_resource(data: dict) -> str:
    """
    Helper function to generate the Terraform resource for a permission set.
    :param data: The data for the permission set
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
    :param data: The data for the permission set
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
    :param data: The data for the permission set
    :return: A list of strings containing the Terraform resource for the permission set's attached customer managed policies.
    :rtype: list[str]
    """
    if "CustomerManagedPolicies" not in data:
        return []

    attachment_strings = []
    for policy_name in data["CustomerManagedPolicies"]:
        path, policy_base_name = parse_customer_managed_policy_reference(policy_name)
        attachment_strings.append(
            f"""
resource "aws_ssoadmin_customer_managed_policy_attachment" "{data["Name"]}_customer_managed_policy_{policy_base_name}" {{
  lifecycle {{
    ignore_changes = [
      instance_arn
    ]
  }}
  instance_arn       = local.sso_instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.{data["Name"]}.arn
  customer_managed_policy_reference {{
    name = "{policy_base_name}"
    path = "{path}"
  }}
}}
"""
        )
    return attachment_strings


def get_permission_set_custom_policy(data: dict, permission_set_file_path: str) -> str:
    """
    Helper function to generate the Terraform resource for a permission set's attached custom/inline policy
    :param data: The data for the permission set
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
    :param data: The data for the permission set
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
    Takes a path to a directory containing permission set files and returns the Terraform resources for the
    permission sets.
    :param template_path: The path to the directory containing permission set files
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
                data = json.load(
                    convert_file,
                )
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
    assigments_files = glob.glob(os.path.join(template_path, "*.yaml"))
    if not assigments_files:
        raise Exception(f"No assignments files found in directory {template_path}")
    assign_dic = {}
    assignments_list = []

    for eachFile in assigments_files:
        with open(eachFile, "r") as convert_file:
            data = yaml.safe_load(
                convert_file,
            )
            assignments_list.extend(data["Assignments"])
    assign_dic["Assignments"] = assignments_list
    log.info("Assignments successfully loaded from repository files")
    return assign_dic


def resolve_ou_names(
    ou_id: str,
    client,
):
    """
    Recursively resolves OU names to a list of all child OU dicts for that OU.
    Used to help resolve OU names to OU IDs.

    Includes itself, unless it's root.
    """
    results = []
    # Include the current OU unless it's the root
    if not re.match(r"^r-", ou_id):
        logging.info(
            f"Resolving OU ID {ou_id} to its name and adding it to the list of OUs to resolve"
        )
        try:
            this_ou = client.describe_organizational_unit(
                OrganizationalUnitId=ou_id,
            )["OrganizationalUnit"]
        except Exception as e:
            logging.error(
                f"Error resolving OU ID {ou_id} to its name. Reason: {repr(e)}"
            )
            raise Exception(
                f"Error resolving OU ID {ou_id} to its name. Reason: {repr(e)}"
            )
        results.append(this_ou)
    # Get its children
    response = client.list_organizational_units_for_parent(ParentId=ou_id)
    children = response["OrganizationalUnits"]
    while "NextToken" in response:
        response = client.list_organizational_units_for_parent(
            ParentId=ou_id, NextToken=response["NextToken"]
        )
        children.extend(response["OrganizationalUnits"])

    if children:
        for each_ou in children:
            results.extend(resolve_ou_names(each_ou["Id"], client))

    return results


def get_all_accounts_in_ou(
    ou_id: str,
    client,
):
    """
    Recursively finds all accounts within an OU and its sub-OUs.
    Inactive accounts will be skipped.

    Returns a list of dicts containing Account information
    Example return value:
    [
        {
            "Id": "111111111111",
            "State": "ACTIVE",
            ...
        },
        {
            "Id": "222222222222",
            "State": "ACTIVE",
            ...
        }
    ]
    """
    all_accounts = []
    all_ous = resolve_ou_names(ou_id, client)
    paginator = client.get_paginator("list_accounts_for_parent")
    for each_ou in all_ous:
        # Use the paginator rather than a hand-rolled NextToken loop: an earlier
        # version paginated against the wrong ParentId, so every page after the first
        # returned accounts from a different OU.
        for page in paginator.paginate(ParentId=each_ou["Id"]):
            for each_account in page["Accounts"]:
                if each_account["State"] == "ACTIVE":
                    all_accounts.append(each_account)

    return all_accounts


def list_accounts_from_tag_target_with_operators(
    identifier: str, all_accounts_map: dict
) -> list:
    """
    Given a tag target identifier of the form "ACCOUNTTAG:<key1>=<value1>&&<key2>=<value2>||<key3>=<value3>", returns a list of account IDs that match the tag criteria following left-to-right order of operations.

    && indicates intersection (logical "AND" operator)
    || indicates union (logical "OR" operator)
    """
    try:
        pattern = re.compile(r"(?P<operator>&&|\|\|)?(?P<key>[^=]+)=(?P<value>[^&|]+)")
        body = identifier[len("ACCOUNTTAG:") :]
        tag_criteria = []
        for match in pattern.finditer(body):
            operator = match.group("operator")
            if operator is None:
                operator = "||"  # Default to OR for the first criteria if no operator is specified
            key = match.group("key")
            value = match.group("value")
            tag_criteria.append((operator, key, value))
    except Exception as e:
        logging.error(
            f"Error parsing tag target identifier '{identifier}'. Tag target identifiers must be in the format 'ACCOUNTTAG:<key>=<value>'. Reason: {repr(e)}"
        )
        raise Exception(
            f"Error parsing tag target identifier '{identifier}'. Tag target identifiers must be in the format 'ACCOUNTTAG:<key>=<value>'. Reason: {repr(e)}"
        )

    current_accounts = set()
    for operator, key, value in tag_criteria:
        accounts_matching_tag_target = []
        # all_accounts_map is a dict that maps names of accounts to a dict of id and a list of tags
        # We need to walk through all entries in the dict and create a list of IDs associated with tags that match
        for account_info in all_accounts_map.values():
            for each_tag_info in account_info.get("tags", []):
                if each_tag_info["Key"] == key and each_tag_info["Value"] == value:
                    accounts_matching_tag_target.append(account_info["id"])
        # Apply the operator function as appropriate
        if operator == "&&":
            current_accounts = current_accounts.intersection(
                set(accounts_matching_tag_target)
            )
        elif operator == "||":
            current_accounts = current_accounts.union(set(accounts_matching_tag_target))

    # Convert from set of IDs to list of dicts
    return_value = []
    for eachAccount in current_accounts:
        return_value.append(
            {
                "Id": eachAccount,
                "State": "ACTIVE",
            }
        )

    return return_value


def list_accounts_in_identifier(
    identifier: str,
    # This account map is expected to include ONLY active accounts
    all_accounts_map: dict,
    all_ous_map: dict,
    boto_config: Config,
    identifier_cache: dict,
):
    """
    Given an identifier (which can be an OU ID, OU name, account name, root ID, a tag target, or literal 'ROOT'), returns a list of all accounts in that OU/root.

    Root will include ALL accounts in the organization (except the management account)
    OU names/IDs WILL be recursively walked; if multiple OUs with the same name are found, an exception will be thrown
    Tag targets take the form "ACCOUNTTAG:<key>=<value>" and will resolve to all accounts with that tag key and value. # TODO - support AND/OR logic

    If the identifier already exists in the cache, just use the locally-stored value
    """
    if identifier in identifier_cache:
        return identifier_cache[identifier], identifier_cache
    results = []
    client = boto3.client(
        "organizations",
        config=boto_config,
    )
    log.info(f"Resolving {identifier} to a list of accounts")
    # An AWS account name can be any printable character, and an OU name is nearly as
    # permissive. Therefore an account or an OU can be named "ROOT", or named to look
    # exactly like a root ID or an OU ID. Such a name is ambiguous, and the branches
    # below would read it as an ID, which is the more dangerous reading: for "ROOT" it
    # grants access to every account in the organization. Refuse to guess.
    if is_organizational_unit_id(identifier) or is_organization_root_id(identifier) or (
        "ROOT" == identifier.upper()
    ):
        if identifier in all_accounts_map or identifier in all_ous_map:
            raise Exception(
                f"The identifier '{identifier}' is the name of an account or an OU, and "
                "it is also a reserved value or an ID format. Rename the account or the "
                "OU, or target it by its ID instead."
            )
    ou_id = None
    # Case for OU ID
    # NOTE: match the complete OU ID. A test for the "ou-" prefix alone would send an
    # account name or an OU name that starts with "ou-" to the Organizations API as an
    # ID. A value that does not match falls through to the name lookup below.
    if is_organizational_unit_id(identifier):
        ou_id = identifier
    elif re.match(r"^ACCOUNTTAG:", identifier):
        accounts_matching_tag_target = list_accounts_from_tag_target_with_operators(
            identifier,
            all_accounts_map,
        )
        if len(accounts_matching_tag_target) == 0:
            logging.warning(
                f"No accounts were found that matched the tag target '{identifier}'"
            )
        results.extend(accounts_matching_tag_target)
    # Case for Root
    # NOTE: match the root ID exactly. A substring test for "r-" would treat any
    # account or OU name containing "r-" (eg. "prod-r-us") as the organization root
    # and silently expand it to every account in the organization.
    elif is_organization_root_id(identifier) or "ROOT" == identifier.upper():
        for each_account in all_accounts_map.values():
            results.append(
                {
                    "Id": each_account["id"],
                    "State": "ACTIVE",
                }
            )
    # Case for free text identifiers
    else:
        if identifier not in all_ous_map and identifier not in all_accounts_map:
            raise Exception(
                f"Could not find a match for identifier '{identifier}' as either an OU or account name. Please check your name and try again."
            )
        if identifier in all_ous_map and identifier in all_accounts_map:
            raise Exception(
                f"The specified identifier '{identifier}' is currently being used as both an account name and OU name. Either rename the Account/OU(s) or specify using their ID."
            )
        if identifier in all_ous_map:
            if len(all_ous_map[identifier]) > 1:
                raise Exception(
                    f"Found multiple matches for identifier '{identifier}' as an OU name. Either rename the OU(s) or specify using their ID."
                )
            ou_id = all_ous_map[identifier][0]["Id"]
        elif identifier in all_accounts_map:
            results.append(
                {
                    "Id": all_accounts_map[identifier]["id"],
                    "State": "ACTIVE",
                }
            )
        else:
            raise Exception(
                f"Could not find a match for identifier '{identifier}' as either an OU or account name. Please check your name and try again."
            )

    # Get all accounts in the OU
    if ou_id is not None:
        results.extend(
            get_all_accounts_in_ou(
                ou_id,
                client,
            )
        )

    # Filter out any inactive accounts
    account_list = []
    for eachResult in results:
        if eachResult["State"] == "ACTIVE":
            account_list.append(eachResult["Id"])
    identifier_cache[identifier] = account_list
    return account_list, identifier_cache


def lookup_principal_id(
    principalName: str,
    principalType: str,
    identity_store_id: str,
    boto_config: Config,
    principal_cache: dict,
) -> str:
    """
    Given an identity store and principal Name and Type, looks up the user ID in the given Identity Store
    Returns: a tuple of (principal ID, updated principal cache)

    Raises if the principal cannot be resolved to exactly one ID. Do not soften this
    into a sentinel return value: an empty principal ID would be written into the
    generated Terraform, which is a silent authorization defect.
    """
    if f"{principalType}|{principalName}" in principal_cache:
        return principal_cache[f"{principalType}|{principalName}"], principal_cache
    # Checked before the lookup so that the message is not swallowed by the except
    # block below. Previously an unrecognised type returned None with no log at all.
    if principalType not in ("USER", "GROUP"):
        raise Exception(
            f"[PR: {principalName}] Unsupported PrincipalType '{principalType}'. "
            "PrincipalType must be exactly 'USER' or 'GROUP'."
        )
    try:
        client = boto3.client(
            "identitystore",
            config=boto_config,
        )
        if principalType == "GROUP":
            response = client.list_groups(
                IdentityStoreId=identity_store_id,
                Filters=[
                    {"AttributePath": "DisplayName", "AttributeValue": principalName},
                ],
            )
            # Error handling in case the group name does not exist or has duplicates
            if len(response["Groups"]) != 1:
                raise Exception(
                    f"It was not possible to lookup target. Reason: Expected 1 result, but got {response['Groups']}"
                )
            principal_id = response["Groups"][0]["GroupId"]
            principal_cache[f"{principalType}|{principalName}"] = principal_id
            return principal_id, principal_cache
        if principalType == "USER":
            response = client.list_users(
                IdentityStoreId=identity_store_id,
                Filters=[
                    {"AttributePath": "UserName", "AttributeValue": principalName},
                ],
            )
            # Error handling in case the user name does not exist or has duplicates
            if len(response["Users"]) != 1:
                raise Exception(
                    f"It was not possible to lookup target. Reason: Expected 1 result, but got {response['Users']}"
                )
            principal_id = response["Users"][0]["UserId"]
            principal_cache[f"{principalType}|{principalName}"] = principal_id
            return principal_id, principal_cache
    except Exception as error:
        log.error(
            f"[PR: {principalName}] [{principalType}]  It was not possible to lookup target. Reason: "
            + repr(error)
        )
        raise Exception(
            f"Unable to resolve principal '{principalName}' of type '{principalType}' "
            f"in identity store {identity_store_id}. Check that the name exactly "
            f"matches a single user or group in Identity Center. Reason: {error}"
        ) from error


def create_permission_set_arn_dict(
    instance_id: str,
    boto_config: Config,
):
    """
    Given an SSO instance_id, returns a dict mapping Permission Set names to ARNs for all permission sets in that SSO instance.
    """
    sso_client = boto3.client(
        "sso-admin",
        config=boto_config,
    )
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


def resolve_targets(
    each_current_assignments: dict,
    all_accounts_map: dict,
    all_ous_map: dict,
    boto_config: Config,
    identifier_cache: dict,
) -> list:
    """
    Given an assignment object, loop through its targets and flatten any OU/root references to the child accounts of that OU/root.

    An OU target is resolved recursively: every account below the OU is included, at any depth.
    If root is specified, all accounts in the Organization (except the management account) will be included.
    """
    account_list = []
    updated_identifier_cache = identifier_cache
    identifier_string = f"{each_current_assignments['Target']}|{each_current_assignments['PrincipalId']}|{each_current_assignments['PermissionSetName']}"
    log.info(f"[Identifier: {identifier_string}] Resolving target in accounts")
    for eachTarget in each_current_assignments["Target"]:
        # Accounts by ID
        # NOTE: an unquoted account ID in YAML is parsed as an int, which loses any
        # leading zero. Validation rejects that, so anything reaching here is either a
        # quoted 12 digit string or a name.
        string_target = str(eachTarget)
        if is_aws_account_id(string_target):
            # An account name can be 12 digits, so a 12 digit target can name one
            # account and hold the ID of another. Refuse to guess which one is meant.
            if string_target in all_accounts_map:
                raise Exception(
                    f"The target '{string_target}' is the name of an account, and it is "
                    "also the format of an account ID. Rename the account, or use the ID "
                    f"of the account named '{string_target}', which is "
                    f"{all_accounts_map[string_target]['id']}."
                )
            account_list.append(string_target)
        # Account names, OUs, and ROOT
        else:
            new_accounts, updated_identifier_cache = list_accounts_in_identifier(
                identifier=string_target,
                all_accounts_map=all_accounts_map,
                all_ous_map=all_ous_map,
                boto_config=boto_config,
                identifier_cache=identifier_cache,
            )
            account_list.extend(new_accounts)
    # Allow for an Exclusions key to remove
    for eachExclusion in each_current_assignments.get("Exclusions", []):
        string_exclusion = str(eachExclusion)
        if is_aws_account_id(string_exclusion):
            try:
                account_list.remove(string_exclusion)
            except ValueError:
                logging.debug(
                    f"Account {eachExclusion} was not in the list of identifiers, no need to remove it"
                )
                pass  # item was not in the list
        else:
            new_accounts, updated_identifier_cache = list_accounts_in_identifier(
                identifier=string_exclusion,
                all_accounts_map=all_accounts_map,
                all_ous_map=all_ous_map,
                boto_config=boto_config,
                identifier_cache=identifier_cache,
            )
            for eachAccount in new_accounts:
                if eachAccount in account_list:
                    try:
                        account_list.remove(eachAccount)
                    except ValueError:
                        logging.debug(
                            f"Account {eachExclusion} was not in the list of identifiers, no need to remove it"
                        )
                        pass  # item was not in the list

    return account_list, updated_identifier_cache


def get_assignment_resource_name(account: str, assignment: dict) -> str:
    """
    Returns the Terraform resource label for an assignment.

    DO NOT change this format. It is the Terraform address of a live resource, so a
    change makes Terraform destroy and create every assignment, which removes access
    for the time between the two operations.

    Note that the four components are joined with no separator, and that the principal
    has every character other than a letter, a digit, a dash or an underscore removed.
    Therefore two different principals can give one label. The caller must check for a
    collision; see create_assignments_manifest_from_repo_assignments.
    """
    pattern = r"[^a-zA-Z0-9-_]"
    escaped_principal = re.sub(pattern, "", assignment["PrincipalId"])
    return (
        f"assignment_{account}{escaped_principal}"
        f"{assignment['PrincipalType']}{assignment['PermissionSetName']}"
    )


def get_assignments_manifest(
    account: str,
    assignment: dict,
    principal_numeric_id: str,
    permission_set_arn_dict: dict,
    control_tower_permission_sets: list,
) -> str:
    """
    Helper function to create a Terraform manifest for each assignment from the provided inputs
    """
    resource_name = get_assignment_resource_name(account, assignment)
    # If managed by Control Tower, just specify the ARN directly, otherwise reference our permission set
    if assignment["PermissionSetName"] in control_tower_permission_sets:
        permission_set_arn = permission_set_arn_dict[assignment["PermissionSetName"]]
        permission_set_argument = f'"{permission_set_arn}"'
    else:
        permission_set_argument = (
            f"aws_ssoadmin_permission_set.{assignment['PermissionSetName']}.arn"
        )
    return f"""
resource "aws_ssoadmin_account_assignment" "{resource_name}" {{
  instance_arn       = local.sso_instance_arn
  permission_set_arn = {permission_set_argument}
  principal_id       = "{principal_numeric_id}"
  principal_type     = "{assignment['PrincipalType']}"
  target_id          = "{account}"
  target_type        = "AWS_ACCOUNT"
}}
"""


def get_all_ous_map(org_client, parent_id, parent_name="", full_result={}):
    """
    Returns a map of all OUs in the Organization, with the OU name as the key and a list of
    objects containing OU IDs and OU full path names for each matching OU name.

    Recursively calls itself.
    """

    paginator = org_client.get_paginator("list_children")
    iterator = paginator.paginate(
        ParentId=parent_id,
        ChildType="ORGANIZATIONAL_UNIT",
    )
    for page in iterator:
        for ou in page["Children"]:
            # 1. Add entry
            # 2. Fetch children recursively
            ou_name = org_client.describe_organizational_unit(
                OrganizationalUnitId=ou["Id"]
            )["OrganizationalUnit"]["Name"]
            if ou_name not in full_result:
                full_result[ou_name] = []
            full_result[ou_name].append(
                {
                    "Id": ou["Id"],
                    "FullPath": f"{parent_name}/{ou_name}",
                }
            )
            full_result = get_all_ous_map(
                org_client=org_client,
                parent_id=ou["Id"],
                parent_name=ou_name,
                full_result=full_result,
            )

    return full_result


def create_assignments_manifest_from_repo_assignments(
    repository_assignments: dict,
    identity_store: str,
    permission_set_name_dict: dict,
    mgmt_only: bool,
    control_tower_permission_sets: list,
    boto_config: Config,
) -> dict:
    """
    Returns a string containing a Terraform manifest with all assignments represented by the template files.
    """
    log.info("Creating assignment dictionary with resolved account names")
    # Keyed by Terraform resource name, so that a name used twice is detected rather
    # than written into the manifest twice.
    generated_resources = {}
    collisions = []
    org_client = boto3.client(
        "organizations",
        config=boto_config,
    )
    management_account = org_client.describe_organization()["Organization"][
        "MasterAccountId"
    ]

    # Get accounts map
    all_accounts_map = {}
    all_accounts_response_list = []
    response = org_client.list_accounts()
    all_accounts_response_list.extend(response.get("Accounts", []))
    # Paginate as appropriate
    while "NextToken" in response:
        response = org_client.list_accounts(NextToken=response["NextToken"])
        all_accounts_response_list.extend(response.get("Accounts", []))
    # Convert list of accounts to map of Names --> IDs
    # NOTE - this requires that all accounts in the Organization are named uniquely.
    for eachAccount in all_accounts_response_list:
        if eachAccount["State"] != "ACTIVE":
            continue
        if eachAccount["Name"] in all_accounts_map:
            raise Exception(
                f"Duplicate account name detected ({eachAccount['Name']}). This is not allowed for this solution and represents a potential point of confusion for operations at large. Please check the account names in your Organization and rename them as necessary."
            )
        all_accounts_map[eachAccount["Name"]] = {
            "id": eachAccount["Id"],
            "tags": org_client.list_tags_for_resource(ResourceId=eachAccount["Id"])[
                "Tags"
            ],
        }

    # Get OUs map
    root_id = org_client.list_roots()["Roots"][0]["Id"]
    all_ous_map = get_all_ous_map(
        org_client=org_client,
        parent_id=root_id,
    )

    resolved_assignments = {}
    resolved_assignments["Assignments"] = []

    identifier_cache = {}
    principal_cache = {}
    for assignment in repository_assignments["Assignments"]:
        accounts, identifier_cache = resolve_targets(
            each_current_assignments=assignment,
            all_accounts_map=all_accounts_map,
            all_ous_map=all_ous_map,
            boto_config=boto_config,
            identifier_cache=identifier_cache,
        )
        principal_numeric_id, principal_cache = lookup_principal_id(
            assignment["PrincipalId"],
            assignment["PrincipalType"],
            identity_store_id=identity_store,
            boto_config=boto_config,
            principal_cache=principal_cache,
        )

        for eachAccount in accounts:
            # This is just fancy XOR logic
            # If the account is the management account and the assignment flag is for management only,
            # then we will add the assignment to the resolved_assignments dictionary.
            # Otherwise, we will skip it.
            # If the account is not the management account and the assignment flag is NOT management only,
            # then we will add the assignment to the resolved_assignments dictionary.
            if (eachAccount == management_account) == (mgmt_only):
                resource_name = get_assignment_resource_name(eachAccount, assignment)
                manifest = get_assignments_manifest(
                    account=eachAccount,
                    assignment=assignment,
                    principal_numeric_id=principal_numeric_id,
                    permission_set_arn_dict=permission_set_name_dict,
                    control_tower_permission_sets=control_tower_permission_sets,
                )
                source = (
                    f"account={eachAccount} "
                    f"principal={assignment['PrincipalId']!r} "
                    f"type={assignment['PrincipalType']} "
                    f"permission_set={assignment['PermissionSetName']!r}"
                )
                existing = generated_resources.get(resource_name)
                if existing is None:
                    generated_resources[resource_name] = {
                        "manifest": manifest,
                        "source": source,
                    }
                elif existing["manifest"] == manifest:
                    # The same assignment appears in more than one input file. Keep one
                    # copy, as the earlier set() did.
                    pass
                else:
                    collisions.append((resource_name, existing["source"], source))

    # Every collision is collected first, so that one run reports all of them.
    if collisions:
        for resource_name, first_source, second_source in collisions:
            log.error(
                f"Terraform resource name collision '{resource_name}':\n"
                f"  A: {first_source}\n"
                f"  B: {second_source}"
            )
        raise Exception(
            f"{len(collisions)} assignment(s) produced a Terraform resource name that "
            "is already in use by a different assignment. The usual cause is that "
            "characters are removed from PrincipalId to build the name, so "
            "'a.b@example.com' and 'ab@example.com' both become 'abexamplecom'. Rename "
            "one of the principals, or use a different permission set for one of them. "
            "The log above names the assignments that collided."
        )

    # Ordered by first appearance, so the generated file is the same on every run.
    return "\n".join(
        each_resource["manifest"] for each_resource in generated_resources.values()
    )


# def resolve_control_tower_permission_set_arns(permission_set_names):
#     all_permission_sets = []
#     return_value = {}


def build_arg_parser() -> argparse.ArgumentParser:
    """
    Builds the command line argument parser. Kept separate from main() so that the
    argument handling can be unit tested without running the script.
    """
    parser = argparse.ArgumentParser(description="AWS SSO Permission Set Management")
    parser.add_argument(
        "--templates-relative-path",
        action="store",
        help="Relative path (from this script) of the directory containing the input assignment files",
        default="./source/assignments/templates",
    )
    parser.add_argument(
        "--permission-sets-template-relative-path",
        action="store",
        help="Relative path (from this script) of the directory containing the input permission set files",
        default="./source/permission_sets/templates",
    )
    parser.add_argument(
        "--mgmt-only",
        # BooleanOptionalAction gives --mgmt-only and --no-mgmt-only. Do not use
        # type=bool: that runs the bool() constructor over the string, so
        # "--mgmt-only False" would evaluate to True.
        action=argparse.BooleanOptionalAction,
        help="Flag to indicate whether to generate management or member assignments. This will override the environment variable MGMT_ONLY, if specified",
        # Defaults to None so that main() can tell "not specified" apart from
        # "explicitly false" and fall back to the MGMT_ONLY environment variable.
        default=None,
    )
    parser.add_argument(
        "--region",
        type=str,
        required=False,
        help="The name of the AWS region your Identity Center lives in (eg. us-east-1)",
    )
    parser.add_argument(
        "--fail-on-types",
        # nargs="+" keeps this a list. Without it, a supplied value is a string, and
        # the membership test in validate_policies becomes a substring test.
        nargs="+",
        default=["ERROR"],
        help="The types of policy findings that should cause the script to fail. Add SECURITY_WARNING to fail on security findings as well as errors.",
    )
    return parser


def main():
    # Environment variable that determines whether to generate management or member
    # assignments. Only used when --mgmt-only/--no-mgmt-only is not passed.
    mgmt_only_env = os.environ.get("MGMT_ONLY", "").lower() in ["true", "1"]

    args = build_arg_parser().parse_args()
    templates_relative_path = args.templates_relative_path
    permission_sets_template_relative_path = args.permission_sets_template_relative_path
    mgmt_only = args.mgmt_only
    fail_on_types = args.fail_on_types
    region = args.region
    if region is not None:
        boto_config = Config(region_name=region)
    else:
        boto_config = Config()

    if mgmt_only is None:
        logging.warning(
            "Neither --mgmt-only nor --no-mgmt-only was specified, falling back to the "
            f"MGMT_ONLY environment variable (resolved to {mgmt_only_env})"
        )
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
    is_valid = iam_identitycenter_validation.main(
        permission_set_templates_path=permission_sets_template_relative_path,
        assignment_templates_path=templates_relative_path,
        fail_on_types=fail_on_types,
    )
    if not is_valid:
        print("Validation failed. Exiting. Fix errors and re-run!")
        sys.exit(1)

    print("#######################################")
    print("# Starting AWS SSO Resolution Section #")
    print("#######################################\n")
    # Config to handle throttling
    config = Config(
        retries={"max_attempts": 1000, "mode": "adaptive"},
        region_name=region,
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
        instance_id=sso_instance_arn,
        boto_config=boto_config,
    )

    # Get assignments for individual accounts and the
    output_assignments_manifest = create_assignments_manifest_from_repo_assignments(
        repository_assignments=repository_assignments,
        identity_store=identity_store,
        permission_set_name_dict=permission_set_name_dict,
        mgmt_only=mgmt_only,
        control_tower_permission_sets=CONTROL_TOWER_PERMISSION_SETS,
        boto_config=boto_config,
    )

    with open(ASSIGNMENTS_MANIFEST_OUTPUT_FILE_PATH, "w") as f:
        f.write(output_assignments_manifest)
        logging.info(output_assignments_manifest)  # So we can see the output

    log.info("Association file successfully created.")


if __name__ == "__main__":
    main()
