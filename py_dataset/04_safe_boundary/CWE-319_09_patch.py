import requests


def login_to_api(
    username: str,
    password: str,
):
    response = requests.post(
        "https://api.example.com/login",
        json={
            "username": username,
            "password": password,
        },
        timeout=10,
    )
    response.raise_for_status()

    return response

