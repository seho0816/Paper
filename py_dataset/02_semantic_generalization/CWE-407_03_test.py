def build_permission_matrix(
    users: list[dict],
    resources: list[dict],
) -> list[dict]:
    matrix = []

    for user in users:
        for resource in resources:
            matrix.append({
                "user_id": user["id"],
                "resource_id": resource["id"],
                "allowed": evaluate_policy(
                    user,
                    resource,
                ),
            })

    return matrix
