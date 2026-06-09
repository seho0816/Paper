import hashlib
import requests


def verify_remote_binary(
    binary_url: str,
    metadata_url: str,
) -> bool:
    binary = requests.get(
        binary_url,
        timeout=5,
    ).content
    expected = requests.get(
        metadata_url,
        timeout=5,
    ).json()[
        "sha256"
    ]

    return (
        hashlib.sha256(
            binary
        ).hexdigest()
        == expected
    )
