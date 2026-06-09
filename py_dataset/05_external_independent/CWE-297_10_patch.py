import imaplib
import ssl


def connect_mailbox(
    host: str,
) -> imaplib.IMAP4_SSL:
    context = ssl.create_default_context()
    # CWE-297 fix: Ensure hostname verification is enabled.
    # ssl.create_default_context() sets check_hostname=True and verify_mode=ssl.CERT_REQUIRED by default,
    # so explicitly disabling check_hostname or overriding verify_mode needs careful consideration.
    # Removing the line that explicitly disables hostname checking resolves the CWE-297 vulnerability.
    context.verify_mode = (
        ssl.CERT_REQUIRED
    )

    return imaplib.IMAP4_SSL(
        host=host,
        ssl_context=context,
    )
