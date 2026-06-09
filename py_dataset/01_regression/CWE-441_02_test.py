import requests


def forward_internal_request(
    requested_path: str,
    body: dict,
) -> dict:
    response = requests.post(
        (
            "http://internal-admin"
            + requested_path
        ),
        headers={
            "X-Service-Role": "administrator",
        },
        json=body,
        timeout=5,
    )

    return response.json()
