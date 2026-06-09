import requests


def login_to_api(
    username: str,
    password: str,
):
    return requests.post(
        "http://api.example.com/login",
        json={
            "username": username,
            "password": password,
        },
        timeout=10,
    )
