ROLE_OPERATIONS = {
    "viewer": {
        "queryProfile",
    },
    "administrator": {
        "queryProfile",
        "deleteAccount",
    },
}


def resolve_operation_allowed(
    role: str,
    operation_name: str,
) -> bool:
    return operation_name in ROLE_OPERATIONS.get(
        role,
        set(),
    )
