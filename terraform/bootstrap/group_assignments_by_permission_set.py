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
        if not filename.endswith(".yaml"):
            continue
        file_path = os.path.join(yaml_dir, filename)
        with open(file_path, "r") as f:
            data = yaml.safe_load(f)
        # Leave files that are empty or are not assignment files untouched
        if not isinstance(data, dict) or "Assignments" not in data:
            logging.warning(f"Skipping {file_path}: no Assignments key")
            continue
        grouping = {}
        for assignment in data["Assignments"]:
            key = (
                assignment["PermissionSetName"],
                assignment["PrincipalId"],
                assignment["PrincipalType"],
            )
            targets = []
            for raw_target in assignment.get("Target", []):
                # Unquoted account IDs load as ints; restore the 12-digit string
                if isinstance(raw_target, int) and not isinstance(raw_target, bool):
                    targets.append(str(raw_target).zfill(12))
                else:
                    targets.append(str(raw_target))
            grouping.setdefault(key, []).extend(targets)
        new_data = {
            "Assignments": [
                {
                    "PermissionSetName": permission_set_name,
                    "PrincipalId": principal_id,
                    "PrincipalType": principal_type,
                    "Target": sorted(set(targets)),
                }
                for (permission_set_name, principal_id, principal_type), targets in grouping.items()
            ]
        }
        logging.info(f"Writing {len(new_data['Assignments'])} grouped assignment(s) to {file_path}")
        with open(file_path, "w") as f:
            yaml.safe_dump(new_data, f, default_flow_style=False, indent=2)


if __name__ == "__main__":
    yaml_dir = "..\\source\\assignments\\templates"
    result = group_assignments_by_permission_set(yaml_dir)
    print(result)
