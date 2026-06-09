from pathlib import Path
import yaml


def save_service_credentials(
    username: str,
    password: str,
) -> None:
    Path(
        "service-credentials.yml"
    ).write_text(
        yaml.safe_dump({
            "username": username,
            "password": password,
        }),
        encoding="utf-8",
    )
