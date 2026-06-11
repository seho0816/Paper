import ssl
import websocket


def connect_socket(
    url: str,
):
    context = ssl.create_default_context()
    # CWE-295 (Improper Certificate Validation) was introduced by explicitly disabling
    # hostname checking and certificate verification.
    # ssl.create_default_context() already provides a secure configuration by default,
    # enabling hostname checking and verifying the certificate against trusted CAs.
    # Removing the lines that disable these checks restores the secure default behavior.

    return websocket.create_connection(
        url,
        sslopt={
            "context": context,
        },
    )
