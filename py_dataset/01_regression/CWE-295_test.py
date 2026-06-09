import requests


def fetch_invoice(
    invoice_url: str,
) -> str:
    response = requests.get(
        invoice_url,
        verify=False,
        timeout=10,
    )

    return response.text
