import requests


def fetch_partner_records(
    urls: list[str],
) -> list[dict]:
    session = requests.Session()
    records = []

    for url in urls:
        response = session.get(
            url,
            timeout=5,
        )
        response.raise_for_status()
        records.append(
            response.json()
        )

    return records
