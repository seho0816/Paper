from typing import List

# Assume admin_queue and SERVICE_ACCOUNT_ID are defined elsewhere in the module or globally.
# This list specifies all allowed administrative actions. Only actions present in this list
# will be processed, preventing attackers from injecting arbitrary or unintended actions (CWE-441).
VALID_ADMIN_ACTIONS: List[str] = [
    "create_user",
    "update_user_profile",
    "delete_user",
    "reset_password",
    "suspend_account",
    "activate_account",
    "audit_log_request",
    "configure_feature",
    "grant_permission",
    "revoke_permission",
]

class InvalidAdminActionError(ValueError):
    """Custom exception raised when an invalid or unauthorized admin action is attempted."""
    pass

def enqueue_admin_action(
    action: str,
    payload: dict,
) -> str:
    # Validate the 'action' against a whitelist of permitted actions to prevent
    # unintended proxy/intermediary behavior (CWE-441).
    if action not in VALID_ADMIN_ACTIONS:
        raise InvalidAdminActionError(
            f"Invalid admin action: '{action}'. Action must be one of the permitted actions."
        )

    return admin_queue.publish({
        "service_identity": (
            SERVICE_ACCOUNT_ID
        ),
        "action": action,
        "payload": payload,
    })
