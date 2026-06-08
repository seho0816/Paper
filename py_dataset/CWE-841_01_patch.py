import secrets


pending_confirmations: dict[str, str] = {}


class AccountEmailService:
    def request_change(self, account: dict, new_email: str) -> dict:
        # CWE-841 Fix: Enforce required workflow step before committing email change.
        # Original code directly updates the email without verifying ownership
        # of the new address, skipping the confirmation step entirely.
        #
        # Correct workflow:
        #   1. Generate a confirmation token and store it
        #   2. Send confirmation to the NEW email address
        #   3. Only update when the user confirms via the token (confirm_change)
        token = secrets.token_urlsafe(32)
        pending_confirmations[token] = new_email
        send_confirmation_email(new_email, token)
        return {"status": "confirmation_sent", "email": new_email}

    def confirm_change(self, account: dict, token: str) -> dict:
        # CWE-841 Fix: Only apply the email change after the confirmation step completes.
        confirmed_email = pending_confirmations.pop(token, None)
        if confirmed_email is None:
            raise ValueError("invalid or expired confirmation token")

        account["email"] = confirmed_email
        account["email_verified"] = True
        save_account(account)
        return account


def send_confirmation_email(email: str, token: str) -> None:
    print(f"confirm link sent to {email}: token={token}")


def save_account(account: dict) -> None:
    print(account["id"], account["email"])