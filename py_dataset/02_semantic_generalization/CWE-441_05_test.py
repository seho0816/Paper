def run_database_maintenance(
    admin_connection,
    maintenance_action: str,
    target: str,
):
    procedure = getattr(
        admin_connection,
        maintenance_action,
    )

    return procedure(
        target
    )
