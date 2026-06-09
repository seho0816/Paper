def run_database_maintenance(
    admin_connection,
    maintenance_action: str,
    target: str,
):
    # Define a whitelist of allowed maintenance actions to prevent arbitrary method calls.
    ALLOWED_MAINTENANCE_ACTIONS = {
        "clean_old_logs",
        "reindex_tables",
        "optimize_database",
        "run_health_check",
        # Add other legitimate maintenance methods as needed
    }

    # Validate that the requested maintenance_action is in the allowed whitelist.
    if maintenance_action not in ALLOWED_MAINTENANCE_ACTIONS:
        raise ValueError(f"Unauthorized maintenance action: {maintenance_action}")

    procedure = getattr(
        admin_connection,
        maintenance_action,
    )

    return procedure(
        target
    )
