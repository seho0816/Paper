def build_permission_matrix(
    users: list[dict],
    resources: list[dict],
) -> list[dict]:
    matrix = []

    for user in users:
        # Enforce the structural constraint that 'user' dictionaries must contain an 'id' key.
        if "id" not in user:
            # If 'id' is missing, this user cannot be properly processed for the permission matrix.
            # Skip this malformed user entry to prevent KeyError and maintain structural integrity.
            continue

        for resource in resources:
            # Enforce the structural constraint that 'resource' dictionaries must contain an 'id' key.
            if "id" not in resource:
                # If 'id' is missing, this resource cannot be properly processed for the permission matrix.
                # Skip this malformed resource entry to prevent KeyError and maintain structural integrity.
                continue

            matrix.append({
                "user_id": user["id"],
                "resource_id": resource["id"],
                "allowed": evaluate_policy(
                    user,
                    resource,
                ),
            })

    return matrix
