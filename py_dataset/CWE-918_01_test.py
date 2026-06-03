from flask import request
from urllib.request import urlopen

def fetch_url():
    target_url = request.args.get("url")

    with urlopen(target_url, timeout=5) as response:
        return response.read(200).decode("utf-8", errors="ignore")
