import requests


def synchronize_policy(
    policy_url: str,
) -> None:
    response = requests.get(
        policy_url,
        timeout=10,
    )
    response.raise_for_status()

    policy_repository.replace(
        response.json()
    )
