import requests
import os

PAYMENT_API_KEY = os.environ["PAYMENT_API_KEY"]
PAYMENT_API_PASSWORD = os.environ["PAYMENT_API_PASSWORD"]


def load_settlement_report() -> dict:
    response = requests.get(
        "https://payments.example.com/api/settlements",
        auth=(
            PAYMENT_API_KEY,
            PAYMENT_API_PASSWORD,
        ),
        timeout=10,
    )
    response.raise_for_status()
    return response.json()
