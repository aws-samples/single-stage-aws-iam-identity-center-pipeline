import argparse
import boto3
import logging
import argparse
import re
from botocore.config import Config

"""
This script is intended to be run from the management account.

This script will create new permission sets for each permission set currently used by the management account.

It will replace the old permission set with the new permission set.

For example, if I had an old permission set called "Admin", this script would...
1. create a copy permission set with the same contents, called "Admin_MGMTACCT"
2. migrate all management account assignments for that PS to the new permission set.
3. NOT change account assignments for the member accounts

This script will handle CT-owned permission sets separately from non-CT owned permission sets.

This script will also look for any member accounts that are using CT-owned permission sets and migrate them to new member-only permission sets.
For example, if I am assigning the `Company_Data_Scientist` group the `AWSAdministratorAccess` permission set, this script will...
1. Duplicate the `AWSAdministratorAccess` permission set to `AWSAdministratorAccess_MEMBER`
2. It will then migrate the assignment to the new permission set.
3. After running this migration, don't use Control Tower permission sets for customer-managed assignments. Use the `_MEMBER` version instead

There are a few implications to using this script:
1. Permission set names, and therefore SSO role names, will change. This may have implications for SCPs that use SSO roles in condition keys; be ready to update SCPs based on these changes.
2. These changes are occurring outside of IAC, meaning that you will need to update IAC code to match these changes; you can use the import scripts in the `bootstrap` folder to accelerate the IAC changes.
3. This script will not update any permission sets or assignments that are owned by Control Tower. It *will* update customer-managed assignments that use CT-owned permission sets.
4. This script may break any existing automation that creates SSO account assignments outside of IaC (some AFT implementations, for example, create SSO roles for new accounts). 
"""

# Set log level to INFO
logging.basicConfig(level=logging.INFO)


def get_log_archive_audit_accounts(boto3_config):
    """
    This function will retrieve the log archive and audit account IDs from Control Tower
    """
    ct_client = boto3.client("controltower", config=boto3_config)
    lz_arn = ct_client.list_landing_zones()["landingZones"][0]["arn"]
    lz_manifest = ct_client.get_landing_zone(landingZoneIdentifier=lz_arn)[
        "landingZone"
    ]["manifest"]
    log_archive_account_id = lz_manifest["centralizedLogging"]["accountId"]
    audit_account_id = lz_manifest["securityRoles"]["accountId"]
    return log_archive_account_id, audit_account_id


def get_management_permisson_sets(
    management_account_id: str,
    boto3_config,
):
    """
    This function will return all permission set ARNs used by the management account.

    It returns a tuple of two lists: one with the non-Control Tower permission set ARNs, and one with the Control Tower permission set ARNs.
    """
    control_tower_permission_set_names = [
        "AWSOrganizationsFullAccess",
        "AWSServiceCatalogEndUserAccess",
        "AWSServiceCatalogAdminFullAccess",
        "AWSPowerUserAccess",
        "AWSAdministratorAccess",
        "AWSReadOnlyAccess",
    ]

    sso_client = boto3.client("sso-admin", config=boto3_config)
    non_ct_permisson_sets = []
    ct_permisson_sets = []
    instance_arn = sso_client.list_instances()["Instances"][0]["InstanceArn"]
    # List all permission sets, paginating as necessary
    response = sso_client.list_permission_sets_provisioned_to_account(
        AccountId=management_account_id, InstanceArn=instance_arn
    )
    permission_sets_all = response["PermissionSets"]
    while "NextToken" in response:
        response = sso_client.list_permission_sets_provisioned_to_account(
            NextToken=response["NextToken"],
            AccountId=management_account_id,
            InstanceArn=instance_arn,
        )
        permission_sets_all.extend(response["PermissionSets"])
    # Walk through all the permission sets
    for permission_set in permission_sets_all:
        if (
            sso_client.describe_permission_set(
                InstanceArn=instance_arn,
                PermissionSetArn=permission_set,
            )["PermissionSet"]["Name"]
            in control_tower_permission_set_names
        ):
            ct_permisson_sets.append(permission_set)
        else:
            non_ct_permisson_sets.append(permission_set)
    return non_ct_permisson_sets, ct_permisson_sets


def duplicate_permisson_set(old_permisson_set_arn, new_suffix, boto3_config):
    """
    This function will create a copy of a permission set with a suffix appended and return the ARN of the new permission set.
    """
    sso_client = boto3.client("sso-admin", config=boto3_config)
    instance_arn = sso_client.list_instances()["Instances"][0]["InstanceArn"]
    old_permisson_set = sso_client.describe_permission_set(
        InstanceArn=instance_arn,
        PermissionSetArn=old_permisson_set_arn,
    )["PermissionSet"]
    if len(old_permisson_set["Name"] + new_suffix) <= 32:
        new_permisson_set_name = old_permisson_set["Name"] + new_suffix
    else:
        new_permisson_set_name = old_permisson_set["Name"].replace("Access", new_suffix)
    # Check final length
    if (len(new_permisson_set_name)) > 32:
        raise Exception(
            f"New permission set name {new_permisson_set_name} is too long. Please shorten it to 32 or fewer characters."
        )
    # Create new permission set
    logging.info(f"Creating new permission set {new_permisson_set_name}")
    # Splat arguments to avoid passing in None
    create_ps_args = {
        "InstanceArn": instance_arn,
        "Name": new_permisson_set_name,
        "SessionDuration": old_permisson_set.get("SessionDuration"),
    }
    if "Description" in old_permisson_set:
        create_ps_args["Description"] = old_permisson_set.get("Description")
    if "RelayState" in old_permisson_set:
        create_ps_args["RelayState"] = old_permisson_set.get("RelayState")

    new_permisson_set_arn = sso_client.create_permission_set(**create_ps_args)[
        "PermissionSet"
    ]["PermissionSetArn"]
    # Copy managed policies
    for managed_policy in sso_client.list_managed_policies_in_permission_set(
        InstanceArn=instance_arn,
        PermissionSetArn=old_permisson_set_arn,
    )["AttachedManagedPolicies"]:
        sso_client.attach_managed_policy_to_permission_set(
            InstanceArn=instance_arn,
            PermissionSetArn=new_permisson_set_arn,
            ManagedPolicyArn=managed_policy["Arn"],
        )
    # Copy inline policy
    old_inline_policy = sso_client.get_inline_policy_for_permission_set(
        InstanceArn=instance_arn,
        PermissionSetArn=new_permisson_set_arn,
    ).get("InlinePolicy", "")
    if old_inline_policy:
        sso_client.put_inline_policy_to_permission_set(
            InlinePolicy=old_inline_policy,
            InstanceArn=instance_arn,
            PermissionSetArn=new_permisson_set_arn,
        )

    # Copy permissions boundaries
    try:
        old_permissions_boundary = (
            sso_client.get_permissions_boundary_for_permission_set(
                InstanceArn=instance_arn,
                PermissionSetArn=new_permisson_set_arn,
            ).get("PermissionsBoundary", "")
        )
    except sso_client.exceptions.ResourceNotFoundException:
        old_permissions_boundary = None
    if old_permissions_boundary:
        sso_client.put_permissions_boundary_to_permission_set(
            PermissionsBoundary=old_permissions_boundary,
            InstanceArn=instance_arn,
            PermissionSetArn=new_permisson_set_arn,
        )
    # Return the new permission set
    return new_permisson_set_arn


def get_principal_name(assignment, identity_store_id, boto3_config):
    identity_store_client = boto3.client("identitystore", config=boto3_config)
    if assignment["PrincipalType"] == "GROUP":
        return identity_store_client.describe_group(
            IdentityStoreId=identity_store_id,
            GroupId=assignment["PrincipalId"],
        )["DisplayName"]
    else:
        return identity_store_client.describe_user(
            IdentityStoreId=identity_store_id,
            UserId=assignment["PrincipalId"],
        )["UserName"]


def migrate_account_assignment(
    assignment,
    new_ps_arn,
    target_account,
    boto3_config,
):
    """
    This function will take an account assignment for a legacy permission set and migrate it to a management-specific permission set.

    It will first create the new account assignment and then delete the old account assignment.
    """
    sso_client = boto3.client("sso-admin", config=boto3_config)
    try:
        target_account_name = boto3.client(
            "organizations", config=boto3_config
        ).describe_account(AccountId=target_account)["Account"]["Name"]
    except Exception:
        target_account_name = target_account
    instances_response = sso_client.list_instances()
    instance_arn = instances_response["Instances"][0]["InstanceArn"]
    identity_store_id = instances_response["Instances"][0]["IdentityStoreId"]
    old_permission_set_name = sso_client.describe_permission_set(
        InstanceArn=instance_arn,
        PermissionSetArn=assignment["PermissionSetArn"],
    )["PermissionSet"]["Name"]
    new_permission_set_name = sso_client.describe_permission_set(
        InstanceArn=instance_arn,
        PermissionSetArn=new_ps_arn,
    )["PermissionSet"]["Name"]
    principal_name = get_principal_name(
        assignment=assignment,
        identity_store_id=identity_store_id,
        boto3_config=boto3_config,
    )
    principal_type = assignment["PrincipalType"]
    logging.info(
        f"Creating new account assignment for account {target_account_name} ({target_account}) with Permission Set Name = {new_permission_set_name} and {principal_type} Principal {principal_name}",
    )
    # Create new assignment
    new_assignment_status = sso_client.create_account_assignment(
        InstanceArn=instance_arn,
        TargetId=target_account,
        TargetType="AWS_ACCOUNT",
        PermissionSetArn=new_ps_arn,
        PrincipalType=assignment["PrincipalType"],
        PrincipalId=assignment["PrincipalId"],
    )["AccountAssignmentCreationStatus"]
    # Delete old assignment
    logging.info(
        f"Deleting old account assignment for account {target_account_name} ({target_account}) with Permission Set Name = {old_permission_set_name} and {principal_type} Principal {principal_name}",
    )
    sso_client.delete_account_assignment(
        InstanceArn=instance_arn,
        TargetId=target_account,
        TargetType="AWS_ACCOUNT",
        PermissionSetArn=assignment["PermissionSetArn"],
        PrincipalType=assignment["PrincipalType"],
        PrincipalId=assignment["PrincipalId"],
    )

    return new_assignment_status


def is_managed_by_control_tower(
    principal_name,
    permission_set,
    account_email,
    is_audit_account: bool = False,
    is_log_archive_account: bool = False,
    is_management_account: bool = False,
) -> bool:
    """
    This function checks if a given account assignment is owned by Control Tower, and returns True if owned by CT and false otherwise.

    This function checks against specific combinations of user/group and permission set names indicate that they are generic default assignments from Control Tower.

    We don't want to manage something that CT manages.
    """

    ct_assignment_strings = [
        f"{account_email}|AWSAdministratorAccess",
        "AWSControlTowerAdmins|AWSOrganizationsFullAccess",
        "AWSControlTowerAdmins|AWSAdministratorAccess",
        "AWSSecurityAuditPowerUsers|AWSPowerUserAccess",
        "AWSSecurityAuditors|AWSReadOnlyAccess",
    ]
    # There are also a few special assignments for the Audit account and Log Archive account and Management Account
    if is_audit_account:
        ct_assignment_strings.append("AWSAuditAccountAdmins|AWSAdministratorAccess")
    if is_log_archive_account:
        ct_assignment_strings.append("AWSLogArchiveAdmins|AWSAdministratorAccess")
        ct_assignment_strings.append("AWSLogArchiveViewers|AWSReadOnlyAccess")
    if is_management_account:
        ct_assignment_strings.append("AWSAccountFactory|AWSServiceCatalogEndUserAccess")
        ct_assignment_strings.append(
            "AWSServiceCatalogAdmins|AWSServiceCatalogAdminFullAccess"
        )

    return f"{principal_name}|{permission_set}" in ct_assignment_strings


def get_permission_set_name_to_arn_map(boto3_config):
    sso_client = boto3.client("sso-admin", config=boto3_config)
    instances_response = sso_client.list_instances()
    instance_arn = instances_response["Instances"][0]["InstanceArn"]
    permission_sets = sso_client.list_permission_sets(InstanceArn=instance_arn)[
        "PermissionSets"
    ]
    permission_set_name_to_arn_map = {}
    for permission_set in permission_sets:
        permission_set_name = sso_client.describe_permission_set(
            InstanceArn=instance_arn,
            PermissionSetArn=permission_set,
        )["PermissionSet"]["Name"]
        permission_set_name_to_arn_map[permission_set_name] = permission_set
    return permission_set_name_to_arn_map


def main(read_only, region):
    boto3_config = Config(region_name=region)
    # Get the management account ID
    management_account_id = boto3.client(
        "organizations", config=boto3_config
    ).describe_organization()["Organization"]["MasterAccountId"]

    # Get all permission sets, broken out by Control Tower ownership
    non_ct_permisson_set_arns, ct_permisson_set_arns = get_management_permisson_sets(
        management_account_id=management_account_id,
        boto3_config=boto3_config,
    )

    # Get the instance ARN
    sso_client = boto3.client("sso-admin", config=boto3_config)
    instance_arn = sso_client.list_instances()["Instances"][0]["InstanceArn"]

    # Create management-only permission sets and migrate management assignments to them
    migrated_permission_set_names = []
    too_long_permission_set_names = []
    for permisson_set_arn in non_ct_permisson_set_arns:
        ps_name = sso_client.describe_permission_set(
            InstanceArn=instance_arn,
            PermissionSetArn=permisson_set_arn,
        )["PermissionSet"]["Name"]
        if re.search(r"_MGMTACCT$", ps_name):
            print(
                f"Skipping migration of permission set {ps_name} (ARN: {permisson_set_arn}) because it already has a management-only version"
            )
            continue
        # Skip and flag permission sets that would exceed the maximum name length
        if len(ps_name) > (32 - len("_MGMTACCT")):
            print(
                f"[ACTION REQUIRED] Skipping migration of permission set {ps_name} (ARN: {permisson_set_arn}) because it would exceed the maximum name length. Create a custom name for this new management permission set."
            )
            too_long_permission_set_names.append(ps_name)
            continue
        if read_only:
            print(
                f"Skipping migration of permission set {ps_name} (ARN: {permisson_set_arn}) because read_only is set to True"
            )
            continue
        new_permisson_set_arn = duplicate_permisson_set(
            permisson_set_arn, "_MGMTACCT", boto3_config
        )
        account_assignments = sso_client.list_account_assignments(
            AccountId=management_account_id,
            InstanceArn=instance_arn,
            PermissionSetArn=permisson_set_arn,
        )["AccountAssignments"]
        for account_assignment in account_assignments:
            migrate_account_assignment(
                assignment=account_assignment,
                new_ps_arn=new_permisson_set_arn,
                target_account=management_account_id,
                boto3_config=boto3_config,
            )
        migrated_permission_set_names.append(ps_name)
    if migrated_permission_set_names:
        print(
            f"[ACTION REQUIRED] Assignments have been migrated for the following permission sets, but YOU WILL NEED TO MANUALLY REMOVE THESE PERMISSION SETS FROM THE LIST OF PERMISSION SETS PROVISIONED TO THE MANAGEMENT ACCOUNT."
        )
        list_of_permission_sets_to_unprovision = "\n".join(
            migrated_permission_set_names
        )
        print(
            f"[ACTION REQUIRED] Permission Sets to unprovision from the management account using the AWS Console:\n {list_of_permission_sets_to_unprovision}"
        )
    if too_long_permission_set_names:
        list_of_permission_sets_to_manually_rename = "\n".join(
            too_long_permission_set_names
        )
        print(
            f"[ACTION REQUIRED] Permission Sets to manually rename, due to exceeding the length cap if additional characters were added on:\n {list_of_permission_sets_to_manually_rename}"
        )

    # Review member accounts that are using CT permission sets and migrate them to member-only permission sets
    log_archive_account, audit_account = get_log_archive_audit_accounts(boto3_config)
    permission_set_name_to_arn_map = get_permission_set_name_to_arn_map(boto3_config)
    for ct_permisson_set_arn in ct_permisson_set_arns:
        # Get the permission set name and print a log
        permission_set_name = sso_client.describe_permission_set(
            InstanceArn=instance_arn,
            PermissionSetArn=ct_permisson_set_arn,
        )["PermissionSet"]["Name"]
        print(
            f"Reviewing Control Tower permission set {permission_set_name}. Any assignments that use this permission set will need to be migrated to their member equivalent."
        )
        # Find accounts using this Permission Set, paginating as necessary
        acc_response = sso_client.list_accounts_for_provisioned_permission_set(
            InstanceArn=instance_arn,
            PermissionSetArn=ct_permisson_set_arn,
        )
        accounts_with_ct_permission_set_provisioned = acc_response["AccountIds"]
        while "NextToken" in acc_response:
            acc_response = sso_client.list_accounts_for_provisioned_permission_set(
                InstanceArn=instance_arn,
                PermissionSetArn=ct_permisson_set_arn,
                NextToken=acc_response["NextToken"],
            )
            accounts_with_ct_permission_set_provisioned.extend(
                acc_response["AccountIds"]
            )
        # Walk through each account
        for (
            account_with_ct_permission_set_provisioned
        ) in accounts_with_ct_permission_set_provisioned:
            # Check if the account is a special CT account
            is_log_archive_account = False
            is_audit_account = False
            is_management_account = False
            if account_with_ct_permission_set_provisioned == log_archive_account:
                is_log_archive_account = True
            if account_with_ct_permission_set_provisioned == audit_account:
                is_audit_account = True
            if account_with_ct_permission_set_provisioned == management_account_id:
                is_management_account = True

            if is_management_account:
                print(
                    "Skipping management account, as its permission sets do not need to be migrated to MEMBER-only versions"
                )
                continue

            # List assignments for the account/permission set
            account_assignments = sso_client.list_account_assignments(
                AccountId=account_with_ct_permission_set_provisioned,
                InstanceArn=instance_arn,
                PermissionSetArn=ct_permisson_set_arn,
            )["AccountAssignments"]
            # Walk through each assignment and migrate to the new permission set (if not owned by CT)
            for account_assignment in account_assignments:
                # Get principal name
                principal_name = get_principal_name(
                    assignment=account_assignment,
                    identity_store_id=sso_client.list_instances()["Instances"][0][
                        "IdentityStoreId"
                    ],
                    boto3_config=boto3_config,
                )
                # Get account email
                account_email = boto3.client(
                    "organizations", config=boto3_config
                ).describe_account(
                    AccountId=account_with_ct_permission_set_provisioned
                )[
                    "Account"
                ][
                    "Email"
                ]
                # Check if the assignment is owned by CT
                if is_managed_by_control_tower(
                    principal_name=principal_name,
                    permission_set=permission_set_name,
                    account_email=account_email,
                    is_audit_account=is_audit_account,
                    is_log_archive_account=is_log_archive_account,
                    is_management_account=is_management_account,
                ):
                    logging.debug(
                        f"Skipping CT-managed assignment of permission set {permission_set_name} and principal {principal_name}"
                    )
                    continue
                if read_only is True:
                    logging.info(
                        f"Would migrate account assignment in account {account_with_ct_permission_set_provisioned} with permission set {permission_set_name} and principal {principal_name} if not running in read-only mode."
                    )
                if read_only is False:
                    # Create a copy of the permission set, if necessary
                    try:
                        new_permission_set_arn = duplicate_permisson_set(
                            ct_permisson_set_arn, "_MEMBER", boto3_config
                        )
                        permission_set_name_to_arn_map[
                            f"{permission_set_name}_MEMBER"
                        ] = new_permission_set_arn
                    except sso_client.exceptions.ConflictException:
                        new_permission_set_arn = permission_set_name_to_arn_map[
                            f"{permission_set_name}_MEMBER"
                        ]
                    # Migrate the member account's assignment to the new member-specific permission set
                    migrate_account_assignment(
                        assignment=account_assignment,
                        new_ps_arn=new_permission_set_arn,
                        target_account=account_assignment["AccountId"],
                        boto3_config=boto3_config,
                    )
    print(f"[ACTION REQUIRED] In case you missed it the first time...")
    print(
        f"[ACTION REQUIRED] Assignments have been migrated for the following permission sets, but YOU WILL NEED TO MANUALLY REMOVE THESE PERMISSION SETS FROM THE LIST OF PERMISSION SETS PROVISIONED TO THE MANAGEMENT ACCOUNT."
    )
    list_of_permission_sets_to_unprovision = "\n".join(migrated_permission_set_names)
    print(
        f"[ACTION REQUIRED] Permission Sets to unprovision from the management account using the AWS Console:\n {list_of_permission_sets_to_unprovision}"
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--region",
        help="Region in which to run this script",
    )
    parser.add_argument(
        "--read-only",
        action="store_true",
        help="If set, this script will not make any changes to the SSO service.",
    )
    args = parser.parse_args()
    read_only = args.read_only
    region = args.region
    main(
        read_only=read_only,
        region=region,
    )
