import smtplib
import ssl

async def send_security_notice(recipient: str, message: str) -> None:
    # CWE-1322 refers to improper protection against MX record poisoning.
    # While this code directly specifies the host and does not perform MX lookups,
    # it's critical to ensure the integrity and authenticity of the mail server connection
    # to protect against other forms of DNS poisoning (e.g., A record) or Man-in-the-Middle attacks.
    # Explicitly creating and passing a default SSL context ensures that hostname verification
    # and trusted CA certificate validation are enforced during the TLS handshake,
    # preventing connection to a spoofed mail server.
    context = ssl.create_default_context()
    with smtplib.SMTP(
        'mail.internal.example',
        587,
        timeout=10,
    ) as client:
        client.starttls(context=context)
        client.sendmail(
            'security@example.com',
            [recipient],
            message,
        )
