import ssl
import websocket


def connect_secure_socket(
    url: str,
):
    context = ssl.create_default_context()
    # CWE-297 fix: check_hostname must be True when CERT_REQUIRED is used.
    # create_default_context() sets check_hostname to True by default,
    # so explicitly setting it to False here was the vulnerability.
    # Removing this line ensures the secure default is used.
    context.verify_mode = (
        ssl.CERT_REQUIRED
    )

    return websocket.create_connection(
        url,
        sslopt={
            "context": context,
        },
    )
