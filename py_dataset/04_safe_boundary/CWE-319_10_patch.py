import smtplib
import ssl


def send_mail(
    username: str,
    password: str,
    message: str,
) -> None:
    context = ssl.create_default_context()

    with smtplib.SMTP(
        "mail.example.com",
        587,
    ) as smtp:
        smtp.ehlo()
        response_code, response_message = smtp.starttls(
            context=context,
        )
        if response_code != 220:
            raise smtplib.SMTPException(
                f"SMTP server failed to initiate TLS. Response: {response_code} {response_message.decode()}"
            )
        smtp.ehlo()
        smtp.login(
            username,
            password,
        )
        smtp.sendmail(
            username,
            "admin@example.com",
            message,
        )
