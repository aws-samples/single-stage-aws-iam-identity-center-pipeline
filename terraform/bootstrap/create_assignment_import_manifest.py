import argparse
import boto3
import json
import logging
from botocore.config import Config
import os
import re
import yaml

logging.basicConfig(level=logging.INFO)

# This function will create a Terraform manifest file used to import existing permission sets into the TF pipeline
# It will also create YAML files that describe the contents of the permission set assignments
# Control Tower-owned assignments will not be imported.
# The YAML files that are outputted will be grouped into files based on the user/group that has the associated entitlements
IMPORTS_FILENAME = os.path.join(".", "import_assignments.tf")
TEMPLATE_OUTPUT_DIRECTORY = "./source/assignments/templates"


def is_managed_by_control_tower(
    principal_name,
    permission_set,
    account_email,
    is_audit_account: bool = False,
    is_log_archive_account: bool = False,
) -> bool:
    # These combinations of user/group and permission set names indicate that they are generic default assignments from Control Tower.
    # If any of these assignments are present, skip and do not import to Terraform. We don't want to manage something that CT manages.
    ct_assignment_strings = [
        f"{account_email}|AWSAdministratorAccess",
        "AWSControlTowerAdmins|AWSOrganizationsFullAccess",
        "AWSControlTowerAdmins|AWSAdministratorAccess",
        "AWSSecurityAuditPowerUsers|AWSPowerUserAccess",
        "AWSSecurityAuditors|AWSReadOnlyAccess",
    ]
    # There are also a few special assignments for the Audit account and Log Archive account
    if is_audit_account:
        ct_assignment_strings.append("AWSAuditAccountAdmins|AWSAdministratorAccess")
    if is_log_archive_account:
        ct_assignment_strings.append("AWSLogArchiveAdmins|AWSAdministratorAccess")
        ct_assignment_strings.append("AWSLogArchiveViewers|AWSReadOnlyAccess")
    return f"{principal_name}|{permission_set}" in ct_assignment_strings


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--region",
        type=str,
        required=True,
        help="The name of the AWS region your Identity Center lives in (eg. us-east-1)",
    )
    parser.add_argument(
        "--log-archive-account-name",
        type=str,
        default="Log Archive",
        help="The name of the Log Archive account in your organization",
    )
    parser.add_argument(
        "--audit-account-name",
        type=str,
        default="Audit",
        help="The name of the Audit account in your organization",
    )
    args = parser.parse_args()
    region = args.region
    log_archive_account_name = args.log_archive_account_name
    audit_account_name = args.audit_account_name
    # Config to handle throttling
    config = Config(
        retries={"max_attempts": 10, "mode": "adaptive"},
        region_name=region,
    )
    sso_client = boto3.client("sso-admin", config=config)
    id_store_client = boto3.client("identitystore", config=config)
    # Find Control Tower accounts so that we avoid importing CT-managed resources
    org_client = boto3.client("organizations", config=config)
    management_account = org_client.describe_organization()["Organization"][
        "MasterAccountId"
    ]
    try:
        # Get all accounts via paginating
        all_accounts = []

        # Do the first run
        initial_response = org_client.list_accounts()
        all_accounts.extend(initial_response["Accounts"])
        next_token = initial_response.get("NextToken")

        # Do the subsequent runs as necessary
        while next_token:
            response = org_client.list_accounts(NextToken=next_token)
            all_accounts.extend(response["Accounts"])

            next_token = response.get("NextToken")

        audit_account_id = [
            acc["Id"] for acc in all_accounts if acc["Name"] == audit_account_name
        ][0]
        log_archive_id = [
            acc["Id"] for acc in all_accounts if acc["Name"] == log_archive_account_name
        ][0]
    except Exception:
        raise Exception(
            "Unable to identify audit/log archive accounts, make sure you are specifying the right names for them."
        )
    # Get SSO instance info
    response = sso_client.list_instances()
    ssoInstanceArn = response["Instances"][0]["InstanceArn"]
    id_store_id = response["Instances"][0]["IdentityStoreId"]
    assignment_dict = (
        {}
    )  # Assignment dict for existing non-management account assignments
    assignment_dict_mgmt = (
        {}
    )  # assignment dict for existing management account assignments
    # Get all permission sets
    next_token = ""  # nosec
    all_permission_set_arns = []
    while True:
        response = sso_client.list_permission_sets(
            InstanceArn=ssoInstanceArn, MaxResults=100, NextToken=next_token
        )
        all_permission_set_arns.extend(response["PermissionSets"])
        next_token = response.get("NextToken")
        if not next_token:
            break

    # Get all accounts in the org, using pagination
    next_token = ""  # nosec
    all_accounts = []
    while True:
        response = org_client.list_accounts(NextToken=next_token)
        all_accounts.extend(response["Accounts"])
        next_token = response.get("NextToken")
        if not next_token:
            break
    # Walk through all accounts in Identity Center, finding how each permission set is assigned
    for account in [acc["Id"] for acc in all_accounts]:
        logging.info(f"Processing account {account}...")
        # If the account is suspended, skip it
        account_response = org_client.describe_account(AccountId=account)["Account"]
        account_status = account_response["Status"]
        account_name = account_response["Name"]
        if account_status == "SUSPENDED":
            logging.warning(
                f"Account {account_name} is suspended and will not be processed"
            )
            continue
        # Flag any attachments for the management account, since the delegated administrator cannot manage it
        is_in_management_account = False
        if account == management_account:
            logging.warning(
                f"{account} is the Management account and cannot be managed from a delegated administrator"
            )
            is_in_management_account = True
        # Check if we're in a Control Tower default account
        if account == audit_account_id:
            logging.warning(
                f"{account} is the Audit account and may have CT-managed assignments"
            )
            is_audit_account = True
        else:
            is_audit_account = False
        if account == log_archive_id:
            logging.warning(
                f"{account} is the Log Archive account and may have CT-managed assignments"
            )
            is_log_archive_account = True
        else:
            is_log_archive_account = False
        # Walk through all permission sets and find their associated account assignments
        for p_set_arn in all_permission_set_arns:
            # Get all account assignments for this permission set, using pagination
            next_token = ""  # nosec
            account_assignments = []
            while True:
                response = sso_client.list_account_assignments(
                    InstanceArn=ssoInstanceArn,
                    AccountId=account,
                    PermissionSetArn=p_set_arn,
                    MaxResults=100,
                    NextToken=next_token,
                )
                account_assignments.extend(response["AccountAssignments"])
                next_token = response.get("NextToken")
                if not next_token:
                    break
            # Generate the import string that Terraform expects
            for account_assignment in account_assignments:
                # This check is added to catch issues where users are deleted without being unassigned, resulting in dangling references
                if account_assignment["PrincipalId"] == "USER":
                    logging.error(
                        f"Account Assignment with Account ID {account_assignment['AccountId']} and Permission Set ARN {account_assignment['PermissionSetArn']} will be skipped as it had 'USER' specified as its Principal ID"
                    )
                    continue
                import_args = {
                    "principal_id": account_assignment["PrincipalId"],
                    "principal_type": account_assignment["PrincipalType"],
                    "target_id": account_assignment["AccountId"],
                    "target_type": "AWS_ACCOUNT",
                    "permission_set_arn": account_assignment["PermissionSetArn"],
                    "instance_arn": ssoInstanceArn,
                    "is_in_management_account": is_in_management_account,
                }
                import_string = ",".join(
                    [
                        import_args["principal_id"],
                        import_args["principal_type"],
                        import_args["target_id"],
                        import_args["target_type"],
                        import_args["permission_set_arn"],
                        import_args["instance_arn"],
                    ]
                )
                # Resolve the principal name
                if account_assignment["PrincipalType"] == "GROUP":
                    principal_name = id_store_client.describe_group(
                        IdentityStoreId=id_store_id,
                        GroupId=account_assignment["PrincipalId"],
                    )["DisplayName"]
                elif account_assignment["PrincipalType"] == "USER":
                    try:
                        principal_name = id_store_client.describe_user(
                            IdentityStoreId=id_store_id,
                            UserId=account_assignment["PrincipalId"],
                        )["UserName"]
                    except id_store_client.exceptions.ResourceNotFoundException:
                        # This check is added to catch issues where users are deleted without being unassigned, resulting in dangling references
                        logging.error(
                            f"Account Assignment with Account ID {account_assignment['AccountId']} and Permission Set ARN {account_assignment['PermissionSetArn']} will be skipped as it had an invalid user specified as its Principal ID"
                        )
                        continue
                if principal_name is None:
                    logging.error(
                        f"Unable to resolve principal name for principal ID {account_assignment['PrincipalId']}. Exiting."
                    )
                    exit(1)
                # Resolve the permission set name
                permission_set_name = sso_client.describe_permission_set(
                    InstanceArn=ssoInstanceArn,
                    PermissionSetArn=account_assignment["PermissionSetArn"],
                )["PermissionSet"]["Name"]
                # Quit if the assignment is a Control Tower default assignment
                if is_managed_by_control_tower(
                    principal_name=principal_name,
                    permission_set=permission_set_name,
                    account_email=org_client.describe_account(AccountId=account)[
                        "Account"
                    ]["Email"],
                    is_audit_account=is_audit_account,
                    is_log_archive_account=is_log_archive_account,
                ):
                    continue
                # Create the index used to identify the assignment in Terraform
                tf_index = "".join(
                    [
                        account_assignment["AccountId"],
                        principal_name,
                        account_assignment["PrincipalType"],
                        permission_set_name,
                    ]
                )
                import_args["permission_set_name"] = permission_set_name
                import_args["principal_name"] = principal_name
                logging.info(
                    f"Adding assignment with permission set name '{permission_set_name}' and principal name '{principal_name}' and account number '{account_assignment['AccountId']}' to TF manifest"
                )

                # Populate the appropriate assignment dictionary, based on whether the assignment is to management or not
                details_map = {"import_string": import_string, "details": import_args}
                if import_args["is_in_management_account"] is False:
                    assignment_dict[tf_index] = details_map
                elif import_args["is_in_management_account"] is True:
                    assignment_dict_mgmt[tf_index] = details_map

    # Create output assignment manifests, splitting by whether they belong to the management account
    assignments_file_list = [
        {
            "file_name": IMPORTS_FILENAME,
            "is_management_assignment": False,
        }
    ]
    for assignment_file in assignments_file_list:
        logging.info(
            f"Writing assignment manifest to {assignment_file['file_name']}..."
        )
        with open(assignment_file["file_name"], "w") as file:
            file.write(
                f"# This file was automatically generated using the {os.path.basename(__file__)} script"
            )
            for tf_index in assignment_dict:
                if assignment_file["is_management_assignment"] != bool(
                    re.search(r"MGMTACCT", tf_index)
                ):
                    logging.debug(
                        f"Skipping writing assignment '{tf_index}' to {assignment_file['file_name']} because of a mismatch in management and non-management account resources."
                    )
                    continue
                # Remove any illegal characters from the Terraform identifier
                pattern = r"[^a-zA-Z0-9-_]"
                escaped_index = re.sub(pattern, "", tf_index)
                file.write(
                    f"""
import {{
  to = aws_ssoadmin_account_assignment.assignment_{escaped_index}
  id = "{assignment_dict[tf_index]["import_string"]}"
}}
    """
                )

    # Write Assignment JSON files to match up with existing resources
    output = {}
    for tf_index in assignment_dict:
        account_target = assignment_dict[tf_index]["details"]["target_id"]
        describe_account_response = org_client.describe_account(
            AccountId=account_target
        )["Account"]
        account_target_name = describe_account_response["Name"]
        if describe_account_response["Status"] == "SUSPENDED":
            logging.warning(f"Skipping SUSPENDED account named {account_target_name}")
            continue
        principal_name = assignment_dict[tf_index]["details"]["principal_name"]
        permission_set_name = assignment_dict[tf_index]["details"][
            "permission_set_name"
        ]
        # Create the output structure for the assignment, grouped by principal name
        if principal_name not in output:
            output[principal_name] = {"Assignments": []}
        output[principal_name]["Assignments"].append(
            {
                "Target": [account_target_name],
                "PrincipalType": assignment_dict[tf_index]["details"]["principal_type"],
                "PrincipalId": principal_name,
                "PermissionSetName": permission_set_name,
            }
        )

    # Walk through the output and create a file for each principal in the templates folder
    os.makedirs(TEMPLATE_OUTPUT_DIRECTORY, exist_ok=True)
    for usergroup in output:
        template_path = os.path.join(
            TEMPLATE_OUTPUT_DIRECTORY, f"{usergroup}-assignments.yaml"
        )
        with open(template_path, "w") as file:
            file.write(yaml.dump(output[usergroup], indent=4))
