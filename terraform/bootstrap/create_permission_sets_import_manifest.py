import boto3
from botocore.config import Config
import json
import logging
import os
import re

logging.basicConfig(level=logging.INFO)

# This function will create a Terraform manifest file used to import existing permission sets into the TF pipeline
# It will also create a Terraform manifest file used to import existing managed policy attachments into the TF pipeline
# It will also create JSON files that describe the contents of the permission sets and managed policy attachments
# Control Tower-owned permission sets and managed policy attachments will not be imported.
REGION = "us-east-2"  # "YOUR_REGION_HERE"
TF_IDENTIFIER = "from_templates"
MEMBER_IMPORTS_DIR = "./member_imports"
MGMT_IMPORTS_DIR = "./management_imports"
for import_dir in [MEMBER_IMPORTS_DIR, MGMT_IMPORTS_DIR]:
    if not os.path.exists(import_dir):
        os.makedirs(import_dir)
PS_FILENAME = os.path.join(MEMBER_IMPORTS_DIR, "import_permission_sets.tf")
PS_FILENAME_MANAGEMENT = os.path.join(
    MGMT_IMPORTS_DIR, "import_permission_sets_mgmt.tf"
)
MANAGED_FILENAME = os.path.join(MEMBER_IMPORTS_DIR, "import_managed_policy_attachs.tf")
MANAGED_FILENAME_MANAGEMENT = os.path.join(
    MGMT_IMPORTS_DIR, "import_managed_policy_attachs_mgmt.tf"
)
INLINE_FILENAME = os.path.join(MEMBER_IMPORTS_DIR, "import_inline_policies.tf")
INLINE_FILENAME_MANAGEMENT = os.path.join(
    MGMT_IMPORTS_DIR, "import_inline_policies_mgmt.tf"
)
BOUNDARY_FILENAME_NON_MANAGEMENT = os.path.join(
    MEMBER_IMPORTS_DIR, "import_permission_boundaries.tf"
)
BOUNDARY_FILENAME_MANAGEMENT = os.path.join(
    MGMT_IMPORTS_DIR, "import_permission_boundaries.tf"
)
PS_TEMPLATE_DIRECTORY = "./source/permission_sets/templates"

if __name__ == "__main__":  # Get Identity Store and SSO Instance ARN
    # These permission sets are created by Control Tower and should not be imported.
    control_tower_permission_set_names = [
        "AWSOrganizationsFullAccess",
        "AWSServiceCatalogEndUserAccess",
        "AWSServiceCatalogAdminFullAccess",
        "AWSPowerUserAccess",
        "AWSAdministratorAccess",
        "AWSReadOnlyAccess",
    ]
    # Config to handle throttling
    config = Config(
        retries={"max_attempts": 1000, "mode": "adaptive"}, region_name=REGION
    )
    sso_client = boto3.client("sso-admin", config=config)
    response = sso_client.list_instances()
    ssoInstanceArn = response["Instances"][0]["InstanceArn"]
    perm_set_dict = {}

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

    for permission_set in all_permission_set_arns:
        perm_description = sso_client.describe_permission_set(
            InstanceArn=ssoInstanceArn, PermissionSetArn=permission_set
        )["PermissionSet"]
        # Skip Control Tower default Permission Sets
        if perm_description["Name"] in control_tower_permission_set_names:
            logging.info(
                f"Skipping Control Tower default Permission Set: {perm_description['Name']}"
            )
            continue

        # Flag if used to determine if the permission set is for the management account
        if bool(re.search(r"MGMTACCT", perm_description["Name"])):
            logging.info(
                f"Found management-account specific Permission Set: {perm_description['Name']}"
            )
            is_for_management_account = True
        else:
            is_for_management_account = False

        # Default Description if not found
        if "Description" not in perm_description:
            logging.warning(
                f"Description not found for permission set {perm_description['Name']}, defaulting to use its name"
            )
            perm_description["Description"] = (
                f"Permission Set for {perm_description['Name']}"
            )

        # Get ARNS for all Managed Policies attached to Permission Set
        perm_managed_policies = (
            sso_client.list_managed_policies_in_permission_set(
                InstanceArn=ssoInstanceArn, PermissionSetArn=permission_set
            )
        )["AttachedManagedPolicies"]
        perm_managed_policy_arns = [d["Arn"] for d in perm_managed_policies]

        # Add permission set info to dict
        logging.info(f"Adding Permission Set: {perm_description['Name']}")
        perm_set_dict[perm_description["Name"]] = {
            "PermissionSet": permission_set,
            "ManagedPolicyArns": perm_managed_policy_arns,
            "Description": perm_description["Description"],
            "SessionDuration": perm_description["SessionDuration"],
            "IsForManagementAccount": is_for_management_account,
        }
        inline_pol = sso_client.get_inline_policy_for_permission_set(
            InstanceArn=ssoInstanceArn, PermissionSetArn=permission_set
        )
        if inline_pol["InlinePolicy"]:
            perm_set_dict[perm_description["Name"]]["CustomPolicy"] = json.loads(
                inline_pol["InlinePolicy"]
            )
        try:
            perm_bound = sso_client.get_permissions_boundary_for_permission_set(
                InstanceArn=ssoInstanceArn, PermissionSetArn=permission_set
            )
        except sso_client.exceptions.ResourceNotFoundException:
            perm_bound = None
        if perm_bound:
            permission_boundary_object = {
                "PolicyType": "AWS",
                "Policy": perm_bound["PermissionsBoundary"]["ManagedPolicyArn"],
            }
            perm_set_dict[perm_description["Name"]][
                "PermissionBoundary"
            ] = permission_boundary_object

    ## Write import files to their proper location
    # Write Permission Set import file
    permission_set_output_file_properties = [
        {
            "file_name": PS_FILENAME,
            "is_for_management_account": False,
        },
        {"file_name": PS_FILENAME_MANAGEMENT, "is_for_management_account": True},
    ]
    for output_file_properties in permission_set_output_file_properties:
        with open(output_file_properties["file_name"], "w") as file:
            file.write(
                f"# This file was automatically generated using the {os.path.basename(__file__)} script"
            )
            for existing in perm_set_dict:
                if (
                    perm_set_dict[existing]["IsForManagementAccount"]
                    != output_file_properties["is_for_management_account"]
                ):
                    continue
                file.write(
                    f"""
import {{
  to = aws_ssoadmin_permission_set.{existing}
  id = "{perm_set_dict[existing]["PermissionSet"]},{ssoInstanceArn}"
}}
    """
                )

    # Write Managed Policy import file
    permission_set_output_file_properties = [
        {
            "file_name": MANAGED_FILENAME,
            "is_for_management_account": False,
        },
        {"file_name": MANAGED_FILENAME_MANAGEMENT, "is_for_management_account": True},
    ]
    for output_file_properties in permission_set_output_file_properties:
        with open(output_file_properties["file_name"], "w") as file:
            file.write(
                f"# This file was automatically generated using the {os.path.basename(__file__)} script"
            )
            for existing in perm_set_dict:
                if (
                    perm_set_dict[existing]["IsForManagementAccount"]
                    != output_file_properties["is_for_management_account"]
                ):
                    continue
                for managed_arn in perm_set_dict[existing]["ManagedPolicyArns"]:
                    managed_policy_name = managed_arn.split("/")[-1]
                    file.write(
                        f"""
import {{
  to = aws_ssoadmin_managed_policy_attachment.{existing}_managed_policy_{managed_policy_name}
  id = "{managed_arn},{perm_set_dict[existing]["PermissionSet"]},{ssoInstanceArn}"
}}
    """
                    )

    # Write inline policy import files
    permission_set_output_file_properties = [
        {
            "file_name": INLINE_FILENAME,
            "is_for_management_account": False,
        },
        {"file_name": INLINE_FILENAME_MANAGEMENT, "is_for_management_account": True},
    ]
    for output_file_properties in permission_set_output_file_properties:
        with open(output_file_properties["file_name"], "w") as file:
            file.write(
                f"# This file was automatically generated using the {os.path.basename(__file__)} script"
            )
            for existing in perm_set_dict:
                if (
                    perm_set_dict[existing]["IsForManagementAccount"]
                    != output_file_properties["is_for_management_account"]
                ):
                    continue
                if "CustomPolicy" in perm_set_dict[existing]:
                    file.write(
                        f"""
import {{
  to = aws_ssoadmin_permission_set_inline_policy.{existing}_custom_policy
  id = "{perm_set_dict[existing]["PermissionSet"]},{ssoInstanceArn}"
}}
"""
                    )

    # Write permission boundary files
    boundary_output_file_properties = [
        {
            "file_name": BOUNDARY_FILENAME_NON_MANAGEMENT,
            "is_for_management_account": False,
        },
        {"file_name": BOUNDARY_FILENAME_MANAGEMENT, "is_for_management_account": True},
    ]
    for boundary_output_file_property in boundary_output_file_properties:
        with open(boundary_output_file_property["file_name"], "w") as file:
            file.write(
                f"# This file was automatically generated using the {os.path.basename(__file__)} script"
            )
            for existing in perm_set_dict:
                if (
                    perm_set_dict[existing]["IsForManagementAccount"]
                    != boundary_output_file_property["is_for_management_account"]
                ):
                    continue
                if "PermissionBoundary" in perm_set_dict[existing]:
                    file.write(
                        f"""
import {{
  to = aws_ssoadmin_permissions_boundary_attachment.{existing}_permission_boundary
  id = "{perm_set_dict[existing]["PermissionSet"]},{ssoInstanceArn}"
}}
"""
                    )

    # Write Permission Set JSON files
    for permission_set_name in perm_set_dict:
        json_contents = {
            "Name": permission_set_name,
            "Description": perm_set_dict[permission_set_name]["Description"],
            "SessionDuration": perm_set_dict[permission_set_name]["SessionDuration"],
            "ManagedPolicies": perm_set_dict[permission_set_name]["ManagedPolicyArns"],
        }
        if "PermissionBoundary" in perm_set_dict[permission_set_name]:
            json_contents["PermissionBoundary"] = perm_set_dict[permission_set_name][
                "PermissionBoundary"
            ]
        if "CustomPolicy" in perm_set_dict[permission_set_name]:
            json_contents["CustomPolicy"] = perm_set_dict[permission_set_name][
                "CustomPolicy"
            ]
        new_file = os.path.join(PS_TEMPLATE_DIRECTORY, f"{permission_set_name}.json")
        with open(new_file, "w") as file:
            file.write(json.dumps(json_contents, indent=4))
