# AWS Identity Center Pipeline (formerly known as SSO)

This solution is adapted from https://github.com/aws-samples/aws-iam-identity-center-pipeline.

## Summary

This pattern helps you to manage [AWS IAM Identity Center](https://aws.amazon.com/iam/identity-center/) permissions in your multi-account environment as code. With this pattern, you will be able to achieve the following defined as code:

- Create, delete and update permission sets
- Create, update or delete assignments from your permission set with your target (AWS accounts, AWS Organization Units, or the entire Organization) with your federated users from your AWS IAM Identity Center Identity Store (e.g. Microsoft Active Directory)

As a rule of thumb, SSO permissions have three components: a **user group** (_who_ is allowed access?), an **account** (_where_ are they allowed access?), and a **permission set** (_what_ access is allowed?).

This repository does NOT manage SSO permissions for the **MANAGEMENT** account. That is the only account that this pipeline is not able to manage, due to delegated administrator requirements. The management account has a separate set of Permission Sets and Assignments that should only be used in the management account (or not at all, preferably...less management access is better).

## Typical Usage

To update the permission sets and assignments, update the YAML files in `source/assignments/templates` and JSON files in `source/permission_set/templates`.

### Why YAML and JSON?

YAML is easier and more flexible for most people (it allows comments!). However, JSON is the format that is used for AWS IAM permission displays in the console, so to allow for easier comparisons between code and console, that section is still maintained via JSON.

## Planning your templates

This pipeline will manage AWS IAM Identity Center permissions using JSON/YAML templates. These templates represent the state of your permission sets and assignments in AWS IAM Identity Center. Template JSON/YAMLs should be stored in their respective `templates` folders: `source/permission_sets/templates` and `source/assignments/templates`. Examples of their content is below.

### Permission Set Templates

This JSON template is used to manage permission sets. Each file represents a Permission Set in the AWS IAM Identity Center. The following fields of the template must be filled out (PermissionBoundary is optional; at least one of ManagedPolicies, CustomerManagedPolicies, or CustomPolicy must be provided):

FILE NAME: `MyTeamAccess.json`

```
{
    "Name": "MyTeamAccess",
    "Description": "My team access in AWS",
    "SessionDuration": "PT4H",
    "ManagedPolicies": [
        "arn:aws:iam::aws:policy/job-function/ViewOnlyAccess"
    ],
    "CustomerManagedPolicies": [
        "myManagedPolicy",
        "anotherMangedPolicy"
    ],
    "PermissionBoundary": {
        "PolicyType": "AWS",
        "Policy": "arn:aws:iam::aws:policy/AdministratorAccess"
    },
    "CustomPolicy": {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "ProductionAllowAccess",
                "Effect": "Allow",
                "Action": [
                    "ec2:*",
                ],
                "Resource": "*"
            }
        ]
    }
}
```

- **Name**
  - Type: String
  - Can be changed after deployed: No
  - Description: Name of the permission set in AWS Identity Center. Once deployed, this field cannot be changed and must be unique.
- **Description**
  - Type: String
  - Can be changed after deployed: Yes
  - Description: Description of the permission set in AWS Identity Center
- **SessionDuration**
  - Type: String
  - Can be changed after deployed: Yes
  - Description: Role session duration in ISO-8601 format
- **ManagedPolicies**
  - Type: List (String)
  - Can be changed after deployed: Yes
  - Description: List of managed policies ARN in the permission set
- **CustomerManagedPolicies**
  - Type: List (String)
  - Can be changed after deployed: Yes
  - Description: Customer Managed policies that will be added to the permission set. It should be the name of the policy, not the ARN
- **PermissionBoundary**
  - Type: String (JSON)
  - Can be changed after deployed: Yes
  - Description: Your permission boundary. PolicyType should be 'AWS' if a AWS managed policy is used as permission boundary and 'Customer' if a Customer Managed Policy is used. The field "Policy" should be the AWS managed policy ARN for AWS managed policy and policy name for Customer Managed Policy.
- **CustomPolicy**
  - Type: String (JSON)
  - Can be changed after deployed: Yes
  - Description: Custom inline policy that will be added to the permission set

> If you are not using any of the fields above, you can remove it from the template.

### Assignment Templates

This YAML template is used to manage the relationship between Principal vs Accounts vs PermissionSets. The following fields of the template must be filled out. The PrincipalId and PermissionSetName must exactly match the Principal Name in Identity Center and Permission Set Name in Identity Center, respectively:

File Name: `LAB-NetworkAdministrator@domain.internal-assignments.yaml`

```
Assignments:
- SID: Root|bmorris@test.lab|ViewOnlyAccess
  PermissionSetName: ViewOnlyAccess
  PrincipalId: bmorris@test.lab
  PrincipalType: USER
  Target:
  - Root # Root is a keyword that indicates the assignment applies to all accounts in the Organization (except the management account)

- SID: company-sbx-airflow|bmorris@test.lab|AdministratorAccessMember
  PermissionSetName: AdministratorAccessMember
  PrincipalId: bmorris@test.lab
  PrincipalType: USER
  Target:
  - company-sbx-airflow # This is the name of the account

```

> The output of the `create_assignment_import_manifest.py` file will group assignment statements into one file per Principal and use the principal name as the file's base name. While you do not need to follow this convention, it greatly simplifies working with the pipeline, as you will be able to see all of a user/group's permissions in one file.

- **SID**
  - Type: String
  - Can be changed after deployed: No
  - Description: Assignment identifier. Must be unique and cannot change
- **Target**
  - Type: List (string)
  - Can be changed after deployed: Yes
  - Description: Target where the principal will have access with a specific permission set. Supports AccountIds, Account Names, Organizational Unit (OU) IDs, Organizational Unit (OU) Names and Root Id or just "Root" (for associating to all accounts). Because account names and OU names are both arbitrary strings, SSO manager will first search for an OU with the given name, and if it does not find an OU with that name, will search for an account with that name instead. Sub-OU names will not be resolved; use an OU ID for any nested OUs.

- **PrincipalType**
  - Type: String
  - Can be changed after deployed: No
  - Description: Type of the principal that will get the assignment. Can be `GROUP` or `USER`
- **PrincipalId**
  - Type: String
  - Can be changed after deployed: No
  - Description: Name of the user in the IdentityStore that will get the assignment.

### Delegated Administrator vs Management Account Ownership of Infrastructure

> Note: If you don't provision any SSO roles in your management account (a best practice to not provision there!), then this section should be fairly straightforward: just don't use the string `MGMTACCT` in any of your file or permission set names.

This solution splits out management of permission sets used by Management/Root account assignments from the permission sets used by non-Management/Root account assignments. Delegated administration is a security best practice recommended by the AWS Security Reference Architecture. However, the delegated administrator account is disallowed from managing the Management/Root account. Therefore, if you provision SSO roles in the management account, two pipelines and parallel sets of permission sets and assignments are required: one for delegated admin, and one for the management account. However, it is preferable to not provision SSO roles in the management account at all. Having no SSO roles in the management account reduces exposure surface and simplifies SSO management.

If you do choose to deploy a management account pipeline, this solution can use a single shared repository as its source. To reconcile where a resource belongs to, a naming convention is used to distinguish between the targets. In this solution, the identifier `MGMTACCT` is used to indicate JSON/YAML files that are part of the management account. Files without that designation will be managed by the delegated administrator account. The validation stage of the pipeline will ensure that `MGMTACCT` permission sets are not assigned to non-management accounts, and that non-`MGMTACCT` permission sets are not assigned to the management account.

> Note: If you specify an SSO assignment using the root ID, the delegated admin pipeline will not apply that assignment to the management account.

## Prerequisites

To deploy this solution, ensure you have the following requirements:

- A multi-account environment with AWS Organizations already set up.
- Access in the Identity Center delegated administrator account.
- A role provisioned using Role Vending Machine.
- A bootstrapped Terraform environment in your delegated administrator account with an S3 bucket to hold TF state and DynamoDB table to manage locks.

## Deploying

1. Determine whether you will deploy in a delegated administrator account or the management account. Delegated administrator is preferable, especially if you do not plan to provision SSO access to the management account. The term `SSO Account` below will refer to whichever account you chose to deploy the pipeline in.
   1. To make an account into a delegated administrator, you will need to log into the management account, navigate to the Identity Center console, go to Settings, and register your selected account as a delegated administrator.
   2. Additionally, this solution relies on delegating certain read-only Organizations permissions to the IdC delegated administrator so that it can resolve OU names into child account names. The permissions required for the delegated administrator are saved in `docs/required_org_permissions.json` and can be provided via the Organizations console in the management account.
2. Update the `backend.tf` file in the root with references to your Terraform state bucket and lock table.
3. Remove any example templates from the `assignments/templates` and `permission_sets/templates` folder.
4. Run the `create_permission_sets_import_manifest.py` script to help generate import files. This will read the existing permission sets in the environment and convert them into Terraform import files and JSON permission sets. It will not import Control Tower-managed permission sets (see the script for details of which it skips).
5. Run the `create_assignment_import_manifest.py` script to help generate assignment files. This will read the existing permission set assignments in the environment and convert them into Terraform import files and YAML assignment files. It will not import Control Tower-managed assignments (see the script for details of which it skips).
6. Make sure that you are using a role with appropriate permissions to create/destroy the resources. Update the configuration in `.github/workflows/.env` with the SSO account ID and pipeline role that will be used to deploy this infrastructure.
7. Upload the files generated by the Python scripts to the CodeCommit repository created by the pipeline. This will trigger a new pipeline run. Merge the code if the changes look accurate.

## Pipeline Overview

This is a typical Terraform pipeline, except that the main files (`permission_sets_auto.tf` and `assignments_auto.tf`) are generated dynamically from source JSON/YAML files.

## Resolve/Plan Action Deep Dive

This solution is abstracted so that day-to-day management only requires updating the JSON/YAML files. However, the underlying Python and Terraform actually resolves the data and applies it to the environment.

### Validate Policy

This checks every custom policy attached to permission sets and flags any overly permissive policies and common anti-patterns (eg. `iam:PassRole` with a wildcard Resource). These findings should be resolved prior to merging code to `main`. Note that this check does not flag overly permissive _managed_ policies (eg. `AdministratorAccess` is typically indicative of an over-permissioned role, but will not be flagged.

### Validate JSON/YAML syntax

The `iam_identitycenter_validation.py` script is called as part of the `resolve_permission_sets_and_assignments.py` script. The validation script will check for any syntactical errors in the JSON/YAML files, and unsupported configurations (like two permission sets with the same name). The script will fail if there is an invalid syntax detected.

### Resolve/Transform Data

Transforming data is the primary function of the `resolve_permission_sets_and_assignments.py` script. Full details of the Python script can be found in the script itself. At a high level, the script will iterate through the contents of the `permission_sets/templates` and `assignments/templates` folders and resolve permission set names to permission set IDs, principal names to principal IDs, and OUs to individual account names, so that Terraform can operate on them. It will also link the assignment resources to their permission set resources in Terraform. The resulting resolved data is saved in two files: `permission_sets_auto.tf` and `assignments_auto.tf`. These Terraform files are never committed to the repository (in fact, they are explicited ignored via `.gitignore`). They are intermediary files that are only created during pipeline execution. If you want to see their contents, you can add a command such as `cat assignments_auto.tf` to the CodeBuild Action, or add configuration in the Build Project to make these Terraform files outputted as artifacts.

### Imports

This solution supports the use of Terraform 1.5+'s `import block` feature. This feature is useful for migrating SSO from non-Terraform management to Terraform management, or for bringing one-off manually-created resources into Terraform's management scope. The `create_*_import_manifest.py` scripts in the root will generate import files split out by whether they apply to the management account or to non-management (`member`) accounts; this is to ensure that management resources are not managed by the delegated administrator account.

You should remove the import block files and import commands from the CodeBuild actions in the pipeline after its first complete run. Imports can cause errors if they refer to resources that have been deleted (eg. if you import a assignment, then update the code to delete that assignment, attempting to import that assignment using a stale import block would cause an error). The opposite of an import is the `terraform state rm` command -- this command will remove a resource from Terraform's state so that it is no longer managed by Terraform.

### Automation and Scale

Because all new accounts in a multi-account environment are moved to a specific AWS Organizational Unit, this automation will run and grant the required permission sets to the account that are specified in the assignment templates as code. Large environments might see a slow down due the amount of API request to AWS Identity Center. Throttling is being managed by Terraform (assignment stage) and boto3 SDK Config (permission set stage).

## Best practices

- This pipeline will manage (create, update and delete) only Permission Sets that are specified in it. Control Tower permission sets will not be modified.
- You will have multiple JSON/YAML templates in the same folder (both for permission sets and assignments). Assignments files should be split into individual files per principal (user/group) for clarity.
- When you remove a template, the pipeline will remove the assignment / permission set
- If you remove an entire assignment YAML block, the pipeline will delete the assignment from AWS IAM Identity Center
- You can't remove a permission set that is assigned to an AWS account
- You can’t manage a permission set that is associated to the Management Account (the assignment script will skip any assignments to the management account)
- You can’t manage predefined (AWS-managed) permission sets type
- You can't have multiple permission sets with the same name
- You can't have multiple assignments with the same SID
- If you change the Permission Set name, it will create a new one and delete the old one. If doing this, make sure to update any assignments that referenced the old name.

> **IMPORTANT**: When you are using Customer Managed Policies, you need to ensure that the policies are already created in AWS accounts you plan to deploy your permission set (this limitation does not apply for inline policies). This is the same for using customer managed policies as Permission Boundaries.

# Integration with Okta

In this model, users/groups are maintained in Active Directory (AD), then AD is synced to Okta, and then Okta is synced to AWS (via SCIM). In order to create assignments in this IaC repository, you will just need to know the name of the user/group that was added to AWS Identity Store via SCIM.
