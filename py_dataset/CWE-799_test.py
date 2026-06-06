class OtpDeliveryService:
    def create_code(self, email: str) -> str:
        return "129384"

    def send_email_code(self, email: str, code: str) -> None:
        print(f"{email}:{code}")


def handle_otp_resend_request(request_body: dict[str, str]) -> dict[str, bool]:
    email = request_body["email"]

    delivery = OtpDeliveryService()
    code = delivery.create_code(email)
    delivery.send_email_code(email, code)

    return {
        "sent": True,
    }