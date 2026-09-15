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
        "/sso/global/anotherManagedPolicy"
    ],
    "AwsPermissionBoundaryArn": "arn:aws:iam::aws:policy/AdministratorAccess",
    "CustomPolicy": {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "ProductionAllowAccess",
                "Effect": "Allow",
                "Action": [
                    "ec2:*"
                ],
                "Resource": "*"
            }
        ]
    }
}
```

Use **either** `AwsPermissionBoundaryArn` **or** `CustomerPermissionBoundary`, never both. If both keys are present, the resolver stops with an error. To use a customer managed policy as the boundary, replace `AwsPermissionBoundaryArn` above with:

```json
{
    "CustomerPermissionBoundary": {
        "Name": "myBoundaryPolicy",
        "Path": "/sso/global/"
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
  - Description: Customer Managed policies that will be added to the permission set. Each entry is the name of the policy, not the ARN. If the policy is not at the root path, prefix the name with its path, **starting with a slash**. The value is split on the last slash: everything before it is the path, and everything after it is the policy name.

    | Value in the file | Resulting path | Valid |
    | --- | --- | --- |
    | `myPolicy` | `/` | Yes |
    | `/sso/global/myPolicy` | `/sso/global/` | Yes |
    | `sso/global/myPolicy` | `sso/global/` | **No.** AWS requires a path that starts with a slash |
    | `arn:aws:iam::111111111111:policy/sso/myPolicy` | `policy/sso/` | **No.** Use a name, not an ARN |

    The last two rows are the trap: they look correct. Validation rejects both, so the error appears on the pull request rather than at `terraform apply`.
- **AwsPermissionBoundaryArn**
  - Type: String
  - Can be changed after deployed: Yes
  - Description: The ARN of an AWS managed policy to use as the permission set's permission boundary. Mutually exclusive with `CustomerPermissionBoundary`.
- **CustomerPermissionBoundary**
  - Type: Object
  - Can be changed after deployed: Yes
  - Description: A customer managed policy to use as the permission set's permission boundary. `Name` is the policy name, not an ARN. `Path` is optional and defaults to `/`; if given, it must start with a slash. Mutually exclusive with `AwsPermissionBoundaryArn`. If both keys are present, the resolver stops with an error.
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
  - '111111111111' # ID of an account. Always quote it, or YAML reads it as a number and removes any leading zero
  - ou-1234-12345678 # ID of an OU
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
  Exclusions:
  - Audit
  - Log archive
- PrincipalId: LAB-NetworkAdministrator@domain.internal
  PrincipalType: GROUP
  PermissionSetName: ViewOnlyAccess
  Target:
  - ACCOUNTTAG:Environment=Production # All accounts tagged Environment=Production
  - ACCOUNTTAG:Team=Platform&&Environment=Dev # Accounts with BOTH tags
```

> The output of the `create_assignment_import_manifest.py` file will group assignment statements into one file per Principal and use the principal name as the file's base name. While you do not need to follow this convention, it greatly simplifies working with the pipeline, as you will be able to see all of a user/group's permissions in one file.

- **Target**
  - Type: List (string)
  - Can be changed after deployed: Yes
  - Description: Where the principal will have access with this permission set. The following target types are supported:

    | Target type | Example | Notes |
    | --- | --- | --- |
    | Account ID | `'111111111111'` | **Always quote it.** Unquoted, YAML reads it as a number and removes any leading zero |
    | Account name | `qa-staging-account` | Account names must be unique across the organization |
    | OU ID | `ou-1234-12345678` | **Recursive**: includes every account below the OU, at any depth |
    | OU name | `SandboxOU` | Also recursive. An error is raised if two OUs share the name |
    | Root ID or `ROOT` | `ROOT` | Every account in the organization. The management account is skipped; see the README |
    | Account tag | `ACCOUNTTAG:Environment=Prod` | See **Account tag targets** below |

    An OU target **is recursive**. A target of a high-level OU therefore grants access in every account below it, however deep. Check the reach of an OU target before you use one.

    An account or an OU can be named to look like an ID, or named `ROOT`, because AWS allows almost any printable character in a name. Such a target is ambiguous, and the resolver stops with an error rather than guess. Rename the account or the OU, or use its ID.
- **Exclusions**
  - Type: List(string)
  - Can be changed after deployed: Yes
  - Description: Targets removed from the resolved list. Useful to grant access to a large OU except for specific accounts or sub-OUs. Supports the same input types as Target.

#### Account tag targets

A target of the form `ACCOUNTTAG:<key>=<value>` resolves to every account carrying that tag key and value. Combine several with `&&` (intersection) and `||` (union):

```yaml
  Target:
  - ACCOUNTTAG:Environment=Production                  # one tag
  - ACCOUNTTAG:Team=Platform&&Environment=Production   # both tags
  - ACCOUNTTAG:Team=Platform||Team=Networking          # either tag
```

Note the following about the operators:

- They are applied strictly left to right. There is no operator precedence and there is no grouping, so `A||B&&C` means `(A||B)&&C`, not `A||(B&&C)`.
- The first criterion needs no operator. If you give one, use `||`: evaluation starts from an empty set, so a leading `&&` intersects with nothing and the result is always empty.
- A tag target that matches no account logs a warning and contributes no accounts. It is not an error.
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
