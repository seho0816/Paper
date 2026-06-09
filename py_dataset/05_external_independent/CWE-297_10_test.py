import imaplib
import ssl


def connect_mailbox(
    host: str,
) -> imaplib.IMAP4_SSL:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = (
        ssl.CERT_REQUIRED
    )

    return imaplib.IMAP4_SSL(
        host=host,
        ssl_context=context,
    )
