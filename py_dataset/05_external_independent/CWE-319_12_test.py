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
    client.connect(
        host,
        1883,
        60,
    )

    return client
