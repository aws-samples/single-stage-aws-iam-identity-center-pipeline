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
## | Shared identifier parsing and matching
## +-----------------------------------

"""
Small, dependency-free helpers for recognising and parsing the identifiers used in
the permission set and assignment template files.

These live in the validation package so that both the validation scripts and
resolve_permission_sets_and_assignments.py can use them. The resolver imports the
validation package, so the dependency must not run the other way.
"""

import re

# An AWS account ID is exactly 12 digits. Callers must use fullmatch (or the
# is_aws_account_id helper): re.match would also accept a longer string of digits, or
# a name that merely starts with 12 digits.
ACCOUNT_ID_REGEX = re.compile(r"\d{12}")

# An AWS Organizations root ID always starts with "r-". Anchor the match: a substring
# test would treat any name containing "r-" as the organization root.
# Pattern from the AWS Organizations API reference: "r-" followed by 4 to 32 lowercase
# letters or digits.
ROOT_ID_REGEX = re.compile(r"r-[0-9a-z]{4,32}")

# Pattern from the AWS Organizations API reference: "ou-" followed by 4 to 32 lowercase
# letters or digits (the ID of the root that holds the OU), then a dash, then 8 to 32
# more lowercase letters or digits.
ORGANIZATIONAL_UNIT_ID_REGEX = re.compile(r"ou-[0-9a-z]{4,32}-[a-z0-9]{8,32}")

# Terraform identifiers (used for resource names) must start with a letter or an
# underscore and may then contain letters, digits, underscores and dashes.
TERRAFORM_IDENTIFIER_REGEX = re.compile(r"[A-Za-z_][A-Za-z0-9_-]*")


def is_aws_account_id(value) -> bool:
    """
    Returns True only if the string form of the value is exactly 12 digits.

    Accepts any type so that callers do not need to stringify first: YAML will parse
    an unquoted account ID as an int.
    """
    return bool(ACCOUNT_ID_REGEX.fullmatch(str(value)))


def is_organization_root_id(value) -> bool:
    """
    Returns True only if the string form of the value is an AWS Organizations root ID.
    """
    return bool(ROOT_ID_REGEX.fullmatch(str(value)))


def is_organizational_unit_id(value) -> bool:
    """
    Returns True only if the string form of the value is an AWS Organizations OU ID.

    A value that starts with "ou-" but does not match the complete pattern is not an
    OU ID. The caller must then use it as an account name or an OU name.
    """
    return bool(ORGANIZATIONAL_UNIT_ID_REGEX.fullmatch(str(value)))


def is_valid_terraform_identifier(value) -> bool:
    """
    Returns True if the string form of the value can be used as a Terraform
    identifier, such as a resource name.
    """
    return bool(TERRAFORM_IDENTIFIER_REGEX.fullmatch(str(value)))


def parse_customer_managed_policy_reference(policy_name: str):
    """
    Splits a customer managed policy reference into its path and its base name, as
    the aws_ssoadmin_customer_managed_policy_attachment resource requires them
    separately.

    Note that the path is returned exactly as written in the template; it is NOT
    normalised. AWS requires a path to start with a slash, so "sso/global/myPolicy"
    yields the invalid path "sso/global/" rather than "/sso/global/". Validation
    rejects any path with no leading slash, so those cases surface on the pull request
    rather than at apply time. That includes an ARN, which is not a supported value:
    the template must hold a policy name, optionally prefixed with its path.

    Examples:
        "myPolicy"                                      -> ("/", "myPolicy")
        "/sso/global/myPolicy"                          -> ("/sso/global/", "myPolicy")
        "sso/global/myPolicy"                           -> ("sso/global/", "myPolicy")
        "arn:aws:iam::111111111111:policy/sso/myPolicy" -> ("policy/sso/", "myPolicy")

    :return: A tuple of (path, policy_base_name)
    :rtype: tuple[str, str]
    """
    pieces = str(policy_name).split(":")[-1].split("/")
    if len(pieces) == 1:
        return "/", pieces[0]
    return "/".join(pieces[:-1]) + "/", pieces[-1]
