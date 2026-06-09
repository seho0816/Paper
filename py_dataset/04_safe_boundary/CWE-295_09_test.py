import requests


def fetch_invoice(
    invoice_url: str,
) -> str:
    response = requests.get(
        invoice_url,
        timeout=10,
    )
    response.raise_for_status()

    return response.text
