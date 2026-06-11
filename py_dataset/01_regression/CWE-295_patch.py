import requests


def fetch_invoice(
    invoice_url: str,
) -> str:
    response = requests.get(
        invoice_url,
        # CWE-295: Improper Certificate Validation.
        # Removed 'verify=False' to enable default SSL/TLS certificate verification.
        # By default, 'verify' is True, ensuring that SSL certificates are validated.
        timeout=10,
    )

    return response.text
