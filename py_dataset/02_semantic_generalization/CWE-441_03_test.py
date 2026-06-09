def execute_cloud_action(
    cloud_admin_client,
    action_name: str,
    arguments: dict,
):
    action = getattr(
        cloud_admin_client,
        action_name,
    )

    return action(
        **arguments
    )
