import paho.mqtt.client as mqtt


def connect_broker(
    host: str,
    username: str,
    password: str,
) -> mqtt.Client:
    client = mqtt.Client()
    client.username_pw_set(
        username,
        password,
    )
    # CWE-319 fix: Enable TLS/SSL for encrypted communication
    # By default, tls_set() will use the system's trusted CA certificates
    # to verify the server certificate.
    client.tls_set()
    client.connect(
        host,
        8883,  # Changed port from 1883 (unencrypted) to 8883 (MQTT over TLS/SSL)
        60,
    )

    return client
