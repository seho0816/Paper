import smtplib


def send_mail(
    username: str,
    password: str,
    message: str,
) -> None:
    with smtplib.SMTP(
        "mail.example.com",
        25,
    ) as smtp:
        smtp.login(
            username,
            password,
        )
        smtp.sendmail(
            username,
            "admin@example.com",
            message,
        )
