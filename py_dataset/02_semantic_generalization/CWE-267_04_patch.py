ACL = {
    "anonymous": {
        "catalog.read",
    },
    "customer": {
        "catalog.read",
        "order.create",
    },
}


def authorize(
    principal_role: str,
    operation: str,
) -> bool:
    return operation in ACL.get(
        principal_role,
        set(),
    )
