registered_accounts = {
    "owner@example.com",
    "staff@example.com",
}


class PasswordRecoveryController:
    def request_reset(self, email: str) -> tuple[int, dict[str, str]]:
        # CWE-204: Observable Discrepancy Fix
        # Always return the same success response to prevent user enumeration,
        # regardless of whether the email is registered or not.
        # The actual email sending logic is conditionally executed.
        if email in registered_accounts:
            send_reset_message(email)

        # Return a consistent success message for both existing and non-existing emails
        # to prevent attackers from discerning valid accounts based on the response.
        return 200, {
            "status": "sent",
            "message": "재설정 메일을 발송했습니다.",
        }


def send_reset_message(email: str) -> None:
    print(email)
