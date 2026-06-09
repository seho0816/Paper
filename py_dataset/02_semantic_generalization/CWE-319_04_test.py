import telnetlib


def configure_router(
    host: str,
    username: str,
    password: str,
) -> None:
    with telnetlib.Telnet(
        host,
        23,
    ) as connection:
        connection.read_until(
            b"login: "
        )
        connection.write(
            username.encode("utf-8")
            + b"\n"
        )
        connection.read_until(
            b"Password: "
        )
        connection.write(
            password.encode("utf-8")
            + b"\n"
        )
