import ssl
import websocket


def connect_socket(
    url: str,
):
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    return websocket.create_connection(
        url,
        sslopt={
            "context": context,
        },
    )
