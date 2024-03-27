## Planning your templates

This pipeline will manage AWS IAM Identity Center permissions using JSON templates. These templates represent the state of your permission sets and assignments in AWS IAM Identity Center. Template JSONs/YAMLs should be stored in their respective `templates` folders: `terraform/source/permission_sets/templates` and `terraform/source/assignments/templates`. Examples of their content is below.

### Why both JSON and YAML?

YAML adds support for comments and better readability, so is the preferred option.

However, the AWS console renders JSON when displaying IAM permissions, so keeping permission sets in JSON keeps the format of permissions consistent.

### Permission Set Templates

This JSON template is used to manage permission sets. Each file represents a Permission Set in the AWS IAM Identity Center. The following fields of the template must be filled out (PermissionBoundary is optional; at least one of ManagedPolicies, CustomerManagedPolicies, or CustomPolicy must be provided):

FILE NAME: `MyTeamAccess.json`

```json
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

```yaml
Assignments:
- PrincipalId: LAB-NetworkAdministrator@domain.internal
  PrincipalType: GROUP
  PermissionSetName: ViewOnlyAccess
  Target:
  - 11111111111 # ID of an account
  - ou-12345678 # ID of an OU
- PrincipalId: LAB-NetworkAdministrator@domain.internal
  PrincipalType: GROUP
  PermissionSetName: ReadOnlyAccess
  Target:
  - SandboxOU # Name of an OU
  - qa-staging-account # Name of an account
- PrincipalId: LAB-NetworkAdministrator@domain.internal
  PrincipalType: GROUP
  PermissionSetName: SecurityAudit
  Target:
  - ROOT # Special keyword to target all accounts in the organization
```

> The output of the `create_assignment_import_manifest.py` file will group assignment statements into one file per Principal and use the principal name as the file's base name. While you do not need to follow this convention, it greatly simplifies working with the pipeline, as you will be able to see all of a user/group's permissions in one file.

- **Target**
  - Type: List (string)
  - Can be changed after deployed: Yes
  - Description: Target where the principal will have access with a specific permission set. Supports AccountIds, Organizational Unit (OU) IDs, Organizational Unit (OU) Names and Root Id or just "Root" (for associating to all accounts). Does not support account names; any names will be interpreted as OU names. Sub-OUs will not be included; only accounts directly attached to the OU will be included.
- **PrincipalType**
  - Type: String
  - Can be changed after deployed: No
  - Description: Type of the principal that will get the assignment. Can be `GROUP` or `USER`
- **PrincipalId**
  - Type: String
  - Can be changed after deployed: No
  - Description: Name of the user in the IdentityStore that will get the assignment.
- **PermissionSetName**
  - Type: String
  - Can be changed after deployed: No
  - Description: The name of the permission set that this principal should have access to in the selected targets. This MUST match the name of a Permission Set in this repository or an externally-managed permission set (eg. Control Tower-managed permission set).