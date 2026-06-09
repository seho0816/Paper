def execute_cluster_action(
    control_plane,
    action: str,
    resource: str,
):
    return control_plane.execute({
        "action": action,
        "resource": resource,
        "credential": SERVICE_TOKEN,
    })
