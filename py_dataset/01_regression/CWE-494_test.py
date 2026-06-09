import requests


def update_plugin(
    update_url: str,
) -> None:
    response = requests.get(
        update_url,
        timeout=10,
    )
    response.raise_for_status()

    exec(
        response.text,
        {},
    )
