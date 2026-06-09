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

    action = getattr(service, action_name)
    return action(user_id)