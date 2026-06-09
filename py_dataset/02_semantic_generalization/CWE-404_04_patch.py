import smtplib


def send_notification(
    host: str,
    sender: str,
    recipient: str,
    message: str,
) -> None:
    with smtplib.SMTP(
        host,
        587,
        timeout=10,
    ) as client:
        client.starttls()
        client.sendmail(
            sender,
            [recipient],
            message,
        )
