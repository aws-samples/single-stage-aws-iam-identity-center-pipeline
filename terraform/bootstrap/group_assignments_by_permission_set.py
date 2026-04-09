"""
Summary

This script will take a directory of YAML files as input.
For each YAML file, it will look through all entries under the Assignments key.
For all assignments with the same PermissionSetName and Principal, it will group all Targets into a single list of
all targets that share that permission set and principal.
"""

import os
import yaml
import logging

# Set log level to INFO
logging.basicConfig(level=logging.INFO)


def group_assignments_by_permission_set(yaml_dir):
    """
    This function takes a directory of YAML files as input.
    It iterates through each YAML file, loads its contents, and extracts the relevant information.
    It groups all targets that share the same PermissionSetName and Principal, and returns a dictionary
    with the grouping information.
    """

    for filename in os.listdir(yaml_dir):
        if filename.endswith(".yaml"):
            grouping = {}
            file_path = os.path.join(yaml_dir, filename)
            with open(file_path, "r") as f:
                data = yaml.safe_load(f)
                for assignment in data.get("Assignments", []):
                    permission_set_name = assignment["PermissionSetName"]
                    principal_id = assignment["PrincipalId"]
                    principal_type = assignment["PrincipalType"]
                    targets_raw = assignment.get("Target", [])
                    # Convert any numeric values in the target list to strings, padded to 12 digits
                    targets = []
                    for raw_target in targets_raw:
                        if isinstance(raw_target, (int, float)):
                            targets.append(f"{raw_target:012d}")
                        else:
                            targets.append(raw_target)

                    key = (permission_set_name, principal_id, principal_type)
                    if key not in grouping:
                        grouping[key] = []
                    grouping[key].extend(targets)
            # Structure the data to dump it to YAML
            logging.warning(
                f"These are the targets: {targets}, and this is the grouping: {grouping}"
            logging.debug(
                f"These are the targets: {targets}, and this is the grouping: {grouping}"
            new_data = {
                "Assignments": [
                    {
                        "PermissionSetName": permission_set_name,
                        "PrincipalId": principal_id,
                        "PrincipalType": principal_type,
                        "Target": sorted(set(targets)),
                    }
                    for (
                        permission_set_name,
                        principal_id,
                        principal_type,
                    ), targets in grouping.items()
                ]
            }
            with open(file_path, "w") as f:
                logging.info(f"Writing to {file_path}")
                logging.info(f"New data: {new_data}")
                yaml.safe_dump(new_data, f, default_flow_style=False, indent=2)
    return


if __name__ == "__main__":
    yaml_dir = "..\\source\\assignments\\templates"
    result = group_assignments_by_permission_set(yaml_dir)
    print(result)
