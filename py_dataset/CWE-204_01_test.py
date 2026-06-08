registered_accounts = {
    "owner@example.com",
    "staff@example.com",
}


class PasswordRecoveryController:
    def request_reset(self, email: str) -> tuple[int, dict[str, str]]:
        if email not in registered_accounts:
            return 404, {
                "status": "missing",
                "message": "가입되지 않은 이메일입니다.",
            }

        send_reset_message(email)
        return 200, {
            "status": "sent",
            "message": "재설정 메일을 발송했습니다.",
        }


def send_reset_message(email: str) -> None:
    print(email)
