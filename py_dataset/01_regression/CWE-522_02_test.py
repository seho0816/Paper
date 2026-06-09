from configparser import ConfigParser
from pathlib import Path


def save_service_password(username: str, password: str) -> None:
    config = ConfigParser()
    config["service"] = {
        "username": username,
        "password": password,
    }
    with (Path.home() / ".service.ini").open("w", encoding="utf-8") as output:
        config.write(output)
