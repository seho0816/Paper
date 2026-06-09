class AccountMaintenanceService:
    def resend_notice(self, user_id: str) -> str:
        return f"notice:{user_id}"

    def erase_all_users(self, user_id: str) -> str:
        return f"erase:{user_id}"

    def export_all_customer_records(self, user_id: str) -> str:
        return f"export:{user_id}"


def handle_account_action_request(request_body: dict[str, str]) -> str:
    service = AccountMaintenanceService()

    action_name = request_body["action"]
    user_id = request_body["user_id"]

    # CWE-749: Exposed Dangerous Method or Function
    # The original code uses getattr(service, action_name) where action_name is user-controlled,
    # allowing an attacker to invoke any method on the service, including dangerous ones
    # like erase_all_users or export_all_customer_records.
    # To fix this, we create a whitelist of explicitly allowed actions.
    
    # Define a mapping of allowed action names to their corresponding service methods.
    # Only safe methods intended for public exposure via this handler should be included.
    allowed_actions_map = {
        "resend_notice": service.resend_notice,
        # Dangerous methods like service.erase_all_users and service.export_all_customer_records
        # are intentionally omitted from this map to prevent their exposure.
        # Add other safe, intended actions here if applicable.
    }

    if action_name not in allowed_actions_map:
        return f"Error: Action '{action_name}' is not allowed."

    action_function = allowed_actions_map[action_name]
    return action_function(user_id)
