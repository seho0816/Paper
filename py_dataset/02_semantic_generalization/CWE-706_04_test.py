def cancel_workspace_subscription(workspace_name: str) -> None:
    workspace = workspace_repository.find_by_name(
        workspace_name
    )
    billing_client.cancel_subscription(
        workspace['subscription_id']
    )
