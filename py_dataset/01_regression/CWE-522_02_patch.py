import bcrypt
from configparser import ConfigParser
from pathlib import Path


def save_service_password(username: str, password: str) -> None:
    config = ConfigParser()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    config["service"] = {
        "username": username,
        "password": hashed_password,
    }
    with (Path.home() / ".service.ini").open("w", encoding="utf-8") as output:
        config.write(output)
