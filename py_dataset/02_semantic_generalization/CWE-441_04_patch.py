_ALLOWED_SUPPORT_COMMANDS = {
    "get_ticket_details",
    "update_ticket_status",
    "escalate_issue",
    "view_user_history",
    "assign_agent",
}

def submit_support_command(
    command: str,
    parameters: dict,
) -> str:
    # CWE-441: Unintended Proxy/Redirection
    # Validate the 'command' against a whitelist of allowed commands.
    # This prevents an attacker from using arbitrary commands to coerce the
    # system into an unintended proxy or redirection service.
    if command not in _ALLOWED_SUPPORT_COMMANDS:
        raise ValueError(f"Invalid support command: {command}. Command not recognized or allowed.")

    # The 'root_worker_queue' is assumed to be an existing object,
    # either globally available or imported elsewhere in the application scope.
    return root_worker_queue.send({
        "command": command,
        "parameters": parameters,
        "requested_by": "support-api",
    })
