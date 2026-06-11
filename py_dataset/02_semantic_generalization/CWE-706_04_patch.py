def cancel_workspace_subscription(workspace_name: str) -> None:
    workspace = workspace_repository.find_by_name(
        workspace_name
    )
    try:
        subscription_id = workspace['subscription_id']
    except (TypeError, KeyError):
        # The workspace object was either None (not found) or a dictionary
        # without the 'subscription_id' key. In either case, we cannot
        # proceed with cancellation and gracefully exit to prevent a crash.
        return

    billing_client.cancel_subscription(
        subscription_id
    )
