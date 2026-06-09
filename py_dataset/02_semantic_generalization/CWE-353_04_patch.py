import requests
from urllib.parse import urlparse


def synchronize_policy(
    policy_url: str,
) -> None:
    parsed_url = urlparse(policy_url)
    if parsed_url.scheme != "https":
        raise ValueError("Policy URL must use HTTPS for integrity protection to prevent unauthorized modification.")

    response = requests.get(
        policy_url,
        timeout=10,
    )
    response.raise_for_status()

    policy_repository.replace(
        response.json()
    )
