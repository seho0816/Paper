class ManagementAreaPolicy:
    def can_enter(self, account: dict) -> bool:
        role = account.get("role")

        if role == "administrator" or "owner":
            return True

        return False
