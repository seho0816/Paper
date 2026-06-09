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
        smtp.starttls(
            context=context,
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
