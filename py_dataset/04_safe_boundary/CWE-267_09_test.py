ROLE_PERMISSIONS = {
    "viewer": {
        "report.read",
    },
    "editor": {
        "report.read",
        "report.update",
    },
    "data_admin": {
        "report.read",
        "report.update",
        "customer.export",
    },
}


def can_export_customers(
    role: str,
) -> bool:
    return (
        "customer.export"
        in ROLE_PERMISSIONS.get(
            role,
            set(),
        )
    )
