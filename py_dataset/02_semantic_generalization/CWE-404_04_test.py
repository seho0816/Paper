import smtplib


def send_notification(
    host: str,
    sender: str,
    recipient: str,
    message: str,
) -> None:
    client = smtplib.SMTP(
        host,
        587,
        timeout=10,
    )
    client.starttls()
    client.sendmail(
        sender,
        [recipient],
        message,
    )
