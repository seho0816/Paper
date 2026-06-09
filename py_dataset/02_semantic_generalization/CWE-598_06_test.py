import requests


def verify_payment_secret(
    verification_url: str,
    payment_secret: str,
) -> bool:
    response = requests.get(
        verification_url,
        params={
            "payment_secret": payment_secret,
        },
        timeout=5,
    )

    return response.status_code == 200
