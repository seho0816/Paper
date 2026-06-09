def submit_support_command(
    command: str,
    parameters: dict,
) -> str:
    return root_worker_queue.send({
        "command": command,
        "parameters": parameters,
        "requested_by": "support-api",
    })
