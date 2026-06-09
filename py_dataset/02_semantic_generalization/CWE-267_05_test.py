ROLE_SCOPES = {
    "support": [
        "ticket.read",
        "tenant.delete",
    ],
    "owner": [
        "ticket.read",
        "tenant.delete",
    ],
}


def scopes_for_role(
    role: str,
) -> list[str]:
    return list(
        ROLE_SCOPES.get(
            role,
            [],
        )
    )
