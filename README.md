# Single-Stage AWS Identity Center (formerly known as SSO) Pipeline 

This pattern helps you to manage [AWS IAM Identity Center](https://aws.amazon.com/iam/identity-center/) permissions in your multi-account environment as code. With this pattern, you will be able to achieve the following defined as code:

- Create, delete and update permission sets
- Create, update or delete assignments from your permission set with your target (AWS accounts, AWS Organization Units, or the entire Organization) with your federated users from your AWS IAM Identity Center Identity Store (e.g. Microsoft Active Directory)

As a rule of thumb, SSO permissions have three components: a **user group** (_who_ is allowed access?), an **account** (_where_ are they allowed access?), and a **permission set** (_what_ access is allowed?).

This repository does NOT manage SSO permissions for the **MANAGEMENT** account. That is the only account that this pipeline is not able to manage, due to delegated administrator requirements. The management account has a separate set of Permission Sets and Assignments that should only be used in the management account. Alternatively, you could choose to not provision any SSO roles to the management account at all: this would align with AWS's recommendation to limit use of the management account for routine tasks.

## Typical Day-to-Day Usage

To update the permission sets and assignments, update the JSON/YAML files in `terraform/source/assignments/templates` and `terraform/source/permission_set/templates` and commit them to your repository. 

Documentation of their content is detailed in the `terraform/source/JSON_Structure.md` file.

## Prerequisites

To deploy this solution, ensure you have the following requirements:

- A multi-account environment with AWS Organizations.
- A CI/CD platform (eg. GitHub Actions) capable of assuming AWS roles securely, running Python3 scripts, and running Terraform version 1.5+ (to support the use of `import` blocks).
- An account to serve as the Identity Center delegated administrator account.
  - A double-warning here: this solution is NOT designed to be run from the management account. Designate a delegated administrator: it's an AWS best practice.
- A role that can be assumed by your pipeline to make SSO changes in the delegated administrator account. This can be provisioned using [Role Vending Machine](https://github.com/aws-samples/role-vending-machine) or another mechanism for granting a pipeline AWS access.
- Infrastructure for Terraform state management, such as an S3 bucket to hold TF state and DynamoDB table to manage locks.

## Deployment Steps

1. **Stage your environment**
   1. Verify the prerequisites above.
   2. Create a repository in your version control system (eg. GitHub) with a copy of this repository's code.
   3. If you have not done so yet, determine the delegated administrator account and configure it. The term `SSO Account` below will refer to the delegated administrator account.
      1. To make an account into a delegated administrator, you will need to log into the management account, navigate to the Identity Center console, go to Settings, and register your selected account as a delegated administrator.
      2. Additionally, this solution relies on delegating certain additional read-only Organizations permissions to the IdC delegated administrator so that it can resolve OU names into child account names. The permissions required for the delegated administrator are saved in `docs/required_org_permissions.json` and can be provided via the Organizations console in the management account.
      3. If you have permission sets that are used by **both** the management account and at least one non-management account (hereafter called "shared permission sets"), you will need to split the shared permission set into 2 permission sets: one for management and one for non-management. This is a limitation of using a [delegated administrator account](https://docs.aws.amazon.com/singlesignon/latest/userguide/delegated-admin.html#delegated-admin-best-practices). This change is most easily accomplished by (in the *management* account) copying the shared permission set and naming the copied permission set "<ORIGINAL_NAME>_MGMTACCT", then updating the management account's assignments to reference that `_MGMTACCT` permission set instead. The scripts in this repository are designed to skip permission sets containing `MGMTACCT`.
2. **Tailor the Terraform Infrastructure**
   1. Update the `backend.tf` file in the root with references to your Terraform state infrastructure.
   2. Update any region specifications to the region that contains your existing SSO Identity Store. Find and replace any values labeled `YOUR_REGION_HERE`.
   3. Remove any example templates from the `terraform/source/assignments/templates` and `terraform/source/permission_sets/templates` folder.
   4. Update the configuration in `.github/workflows/.env` with the SSO account ID and pipeline role that will be used to deploy this infrastructure. Make sure that you are using a pipeline role with appropriate permissions to create/destroy the resources. 
3. **Generate imports and JSON/YAML files**
   1. These steps are intended for the delegated administrator account. You should assume local credentials that allow you to access the delegated administrator account. The scripts will not touch `MGMTACCT` resources; this will only onboard non-management resources to Terraform.
   2. From the `terraform` folder (`cd terraform`), run `python3 ./bootstrap/create_permission_sets_import_manifest.py --region <YOUR CONTROL TOWER HOME REGION>`  to help generate import files. This will read the existing permission sets in the environment and convert them into Terraform import files and JSON permission sets. It will not import Control Tower-managed permission sets (see the script for details of which it skips). If running from the management account, add the `--non-delegated-admin-mode` flag to ensure that management permission sets are not skipped.
   3. From the `terraform` folder (`cd terraform`), run `python3 ./bootstrap/create_assignment_import_manifest.py --region <YOUR CONTROL TOWER HOME REGION>`  to help generate assignment files. This will read the existing permission set assignments in the environment and convert them into Terraform import files and YAML assignment files. It will not import Control Tower-managed assignments (see the script for details of which it skips).
   4. If you specified `--non-delegated-admin-mode`, review the contents of the `member_imports` folder. If the contents look good, **move** the `member_imports/import_*.tf` files to the `terraform` folder and delete the `member_imports` folder.
      1. The scripts will also generate a `management_imports` folder for reference. You may review this to understand what resources are not accessible by the delegated administrator account. However, this `management_imports` folder is not used for this delegated administrator solution and should be deleted.
   5. If you did not specify `--non-delegated-admin-mode`, then your `import_*.tf` files (excluding management account imports) will automatically be moved to the `terraform` folder. Review them to ensure accuracy.
   6. Review the contents of the `terraform/import_assignments.tf` file.
   7. Review the contents of the `terraform/source/assignments/templates` and `terraform/source/permission_sets/templates` folders. These should now contain automatically-generated JSON/YAML files corresponding to your existing IdC infrastructure.
4. **Configure your CI/CD pipeline**
   1. Configure your CI/CD pipeline so that the Python data resolution script `resolve_permission_sets_and_assignments.py` is run before every `terraform plan` operation.
      1. If you do not do this, `terraform` will not have resolved data to operate on.
      2. The data resolution script also includes a call to the validation script, so you do not need to call the validation script separately.
   2. For an example of how to implement this in GitHub Actions, see the `.github/workflows` folder, specifically the `terraform.yaml` file.
      1. For an example of how to configure a pipeline role for GitHub Actions, see the [role vending machine repository](https://github.com/aws-samples/role-vending-machine).
   3. For an example of how to implement this in CodeBuild, see the `docs/buildspec.yaml` file.
   4. For an example of how to implement this in GitLab, see the `.gitlab` folder.
   5. You may need to adapt these examples to meet your enterprise's CI/CD needs.
5. **Validate and Optimize**
   1.  Note: If you are running `terraform` *locally* to test your setup, you must run `resolve_permission_sets_and_assignments.py` locally before running any `terraform plan` operations. Otherwise, `terraform` will not have the resolved data to refer to.
   2.  Commit the files generated by the Python scripts to a feature branch of your repository. If using the GitHub workflows provided in `.github/workflows`, this will trigger a new pipeline run to perform a `terraform plan`.
   3.  Validate your `terraform plan` output. There should ONLY be imports, and potentially changes to `tags_all` if you keep the default `sso_pipeline=true` tag.
   4.  Merge the code to the `main` branch if the changes look accurate. If using the GitHub workflows provided in `.github/workflows`, merging to `main` will trigger a new pipeline run to perform a `terraform apply`.
   5.  Remove the import files (`import_assignments.tf`, `import_inline_policies.tf`, etc.) after the pipeline's first complete run. Imports can cause errors if they refer to resources that have been deleted (eg. if you import a assignment, then update the code to delete that assignment, attempting to import that assignment using a stale import block would cause an error). Make sure to commit the removal of the files.
   6.  [Optional] Consider consolidating assignments by OU. For a given user/permission set, the import script will create one assignment item per account. If you grant access to all accounts in an OU, you can instead put the OU ID (or `'ROOT'` for all accounts) as the target instead of the account ID. Note that OU-based assignments will only grant access to accounts directly within the OU, not accounts in sub-OUs. Also note that `'ROOT'` will not create an assignment for the management account, because of the limitations of the delegated administrator account. 
   7. Verify branch protection rules. Verify that your `main` branch has branch protection rules that, at minimum, require all changes to be done through pull requests with at least 1 approval.

## External Changes

You may want to configure automation to re-run this pipeline's `terraform apply` action whenever there is an account created or change to the OU structure, so that the appropriate access is provisioned automatically. For an outline of how to achieve that, see `.github/workflows/remote_terraform.yaml`.

## Delegated Administrator vs Management Account Ownership of Infrastructure

> Note: If you don't provision any SSO roles in your management account (a best practice to not provision there!), then this section should be fairly straightforward: just don't use the string `MGMTACCT` in any of your file or permission set names.

This solution splits out management of permission sets used by Management/Root account assignments from the permission sets used by non-Management/Root account assignments. Delegated administration is a security best practice recommended by the AWS Security Reference Architecture. However, the delegated administrator account is disallowed from managing the Management/Root account. Therefore, if you provision SSO roles in the management account, two pipelines and parallel sets of permission sets and assignments are required: one for delegated admin, and one for the management account. However, it is preferable to not provision SSO roles in the management account at all. Having no SSO roles in the management account reduces exposure surface and simplifies SSO management.

To reconcile where a resource belongs to, this solutions establishes a naming convention to distinguish between targets: the identifier `MGMTACCT` is used to indicate JSON files that are part of the management account. Files without the string `MGMTACCT` are assumed to be managed by the delegated administrator account. The validation stage of the pipeline will ensure that `MGMTACCT` permission sets are not assigned to non-management accounts, and that non-`MGMTACCT` permission sets are not assigned to the management account.

## Pipeline Overview

This is a typical Terraform pipeline, except that the main files (`permission_sets_auto.tf` and `assignments_auto.tf`) are generated dynamically from source JSON/YAML files.

## Resolve/Plan Action Deep Dive

This solution is abstracted so that day-to-day management only requires updating the JSON/YAML files. However, the underlying Python and Terraform actually resolves the data and applies it to the environment.

### Validate Policy

This checks every custom policy attached to permission sets and flags any overly permissive policies and common anti-patterns (eg. `iam:PassRole` with a wildcard Resource). These findings should be resolved prior to merging code to `main`. Note that this check does not flag overly permissive _managed_ policies (eg. `AdministratorAccess`) is typically indicative of an over-permissioned role, but will not be flagged.

### Validate JSON/YAML syntax

The `iam_identitycenter_validation.py` script is called as part of the `resolve_permission_sets_and_assignments.py` script. The validation script will check for any syntactical errors in the JSON/YAML files, and unsupported configurations (like two permission sets with the same name). The script will fail if there is an invalid syntax detected.

### Resolve/Transform Data

Transforming data is the primary function of the `resolve_permission_sets_and_assignments.py` script. Full details of the Python script can be found in the script itself. At a high level, the script will iterate through the contents of the `permission_sets/templates` and `assignments/templates` folders and resolve permission set names to permission set IDs, principal names to principal IDs, and OUs to individual account names, so that Terraform can operate on them. It will also link the assignment resources to their permission set resources in Terraform. The resulting resolved data is saved in two files: `permission_sets_auto.tf` and `assignments_auto.tf`. These Terraform files are never committed to the repository (in fact, they are explicited ignored via `.gitignore`). They are intermediary files that are only created during pipeline execution. If you want to see their contents, you can add a command such as `cat assignments_auto.tf` to the CodeBuild Action, or add configuration in the Build Project to make these Terraform files outputted as artifacts.

### Imports

This solution relies on Terraform 1.5+'s `import block` feature. This feature is useful for migrating SSO from non-Terraform management to Terraform management, or for bringing one-off manually-created resources into Terraform's management scope. The `create_*_import_manifest.py` scripts in the `terraform` folder will generate import files split out by whether they apply to the management account or to non-management (`member`) accounts; this is to ensure that management resources are not managed by the delegated administrator account.

You should remove the import block files after the pipeline's first complete run. Imports can cause errors if they refer to resources that have been deleted (eg. if you import a assignment, then update the code to delete that assignment, attempting to import that assignment using a stale import block would cause an error). The opposite of an import is the `terraform state rm` command -- this command will remove a resource from Terraform's state so that it is no longer managed by Terraform.

### Automation and Scale

Because all new accounts in a multi-account environment are moved to a specific AWS Organizational Unit, this automation will run and grant the required permission sets to the account that are specified in the assignment templates as code. Large environments might see a slow down due the amount of API request to AWS Identity Center. Throttling is being managed by Terraform (assignment stage) and boto3 SDK Config (permission set stage).

## Best practices

- This pipeline will manage (create, update and delete) only Permission Sets that are specified in it. Control Tower permission sets will not be modified.
- You will have multiple JSON/YAML templates in the same folder (both for permission sets and assignments). Assignments files should be split into individual files **per principal** (user/group) for clarity.
- When you remove a template, the pipeline will remove the assignment / permission set
- If you remove an entire assignment YAML block, the pipeline will delete the assignment from AWS IAM Identity Center
- You can't remove a permission set that is assigned to an AWS account
- You can’t manage a permission set that is associated to the Management Account (the assignment script will skip any assignments to the management account)
- You can’t manage predefined (AWS-managed) permission sets type
- You can't have multiple permission sets with the same name
- You can't have multiple assignments with the same SID
- If you change the Permission Set name, it will create a new one and delete the old one. If doing this, make sure to update any assignments that referenced the old name.

> **IMPORTANT**: When you are using Customer Managed Policies and/or Customer Managed Permission Boundaries, you need to ensure that the policies are already created in AWS accounts you plan to deploy your permission set (this limitation does not apply for inline policies).

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## Acknowledgements

This is adapted from https://github.com/aws-samples/aws-iam-identity-center-pipeline. It improves on that solution by moving the pipeline to a single-stage.

## AWS Prescriptive Guidance

This artifact is published as AWS Prescriptive Guidance. You can find it with the title `How to deploy IAM Identity Center (SSO) via a Single-Stage Terraform Pipeline`.

## Contributors

- Benjamin Morris (primary developer)
- Andre Cavalcante (developer of [this project's inspiration](https://github.com/aws-samples/aws-iam-identity-center-pipeline))
- Todd O'Boyle (security reviewer and unit test developer)