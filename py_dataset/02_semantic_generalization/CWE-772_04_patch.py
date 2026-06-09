import requests

def proxy_partner_document(document_id: str):
    response = requests.get(
        f'https://partner.example/documents/{document_id}',
        # stream=True is removed. By default, stream is False.
        # This ensures the response body is downloaded and the connection is closed
        # automatically before the Response object is returned, releasing the resource.
        timeout=10,
    )
    response.raise_for_status()
    return response.raw
