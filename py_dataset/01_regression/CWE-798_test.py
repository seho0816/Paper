import requests

PAYMENT_API_KEY = "pay_live_8f04c9a27d6f"
PAYMENT_API_PASSWORD = "payment-admin-2026!"


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
