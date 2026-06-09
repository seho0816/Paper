import smtplib

async def send_security_notice(recipient: str, message: str) -> None:
    with smtplib.SMTP(
        'mail.internal.example',
        587,
        timeout=10,
    ) as client:
        client.starttls()
        client.sendmail(
            'security@example.com',
            [recipient],
            message,
        )
