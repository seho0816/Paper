def execute_cluster_action(
    control_plane,
    action: str,
    resource: str,
):
    allowed_actions = {"start", "stop", "reboot", "status", "scale"}

    if action not in allowed_actions:
        raise ValueError(f"Action '{action}' is not allowed. Permitted actions are: {', '.join(sorted(allowed_actions))}")

    return control_plane.execute({
        "action": action,
        "resource": resource,
        "credential": SERVICE_TOKEN,
    })
