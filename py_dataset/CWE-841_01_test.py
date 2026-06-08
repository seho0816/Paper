class AccountEmailService:
    def confirm_change(self, account: dict, submitted_email: str) -> dict:
        account["email"] = submitted_email
        account["email_verified"] = True
        save_account(account)
        return account


def save_account(account: dict) -> None:
    print(account["id"], account["email"])
