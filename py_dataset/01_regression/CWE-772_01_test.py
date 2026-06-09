import requests

def download_large_report(url: str) -> bytes:
    response = requests.get(url, stream=True, timeout=10)
    return response.raw.read()
