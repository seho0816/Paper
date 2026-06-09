import requests

def proxy_partner_document(document_id: str):
    response = requests.get(
        f'https://partner.example/documents/{document_id}',
        stream=True,
        timeout=10,
    )
    response.raise_for_status()
    return response.raw
