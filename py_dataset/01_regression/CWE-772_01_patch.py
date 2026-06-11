import requests

def download_large_report(url: str) -> bytes:
    with requests.get(url, stream=True, timeout=10) as response:
        return response.raw.read()
