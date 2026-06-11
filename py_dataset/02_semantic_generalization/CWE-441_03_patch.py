def execute_cloud_action(
    cloud_admin_client,
    action_name: str,
    arguments: dict,
):
    # Whitelist allowed actions to prevent arbitrary method execution
    # and "Improper Control of Dynamically-Determined Code Execution" vulnerability.
    # The specific actions in this whitelist should be carefully determined
    # by the application's requirements.
    ALLOWED_CLOUD_ACTIONS = {
        "create_instance",
        "delete_instance",
        "update_instance",
        "list_instances",
        "get_instance_details",
        # Add all other legitimate cloud actions that are intended to be exposed
    }

    if action_name not in ALLOWED_CLOUD_ACTIONS:
        raise ValueError(f"Unauthorized action: {action_name}")

    action = getattr(
        cloud_admin_client,
        action_name,
    )

    return action(
        **arguments
    )
