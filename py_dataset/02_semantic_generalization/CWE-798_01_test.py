import smtplib

SMTP_HOST = "smtp.example.com"
SMTP_USERNAME = "notification-service"
SMTP_PASSWORD = "MailService-Secret-2026"


def send_notification(
    recipient: str,
    message: str,
) -> None:
    with smtplib.SMTP_SSL(SMTP_HOST, 465) as server:
        server.login(
            SMTP_USERNAME,
            SMTP_PASSWORD,
        )
        server.sendmail(
            "noreply@example.com",
            recipient,
            message,
        )
