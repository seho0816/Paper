import hashlib
import requests
import re

# Define a regex pattern for a valid SHA256 hexadecimal string
# It must be exactly 64 characters long and contain only hex digits.
SHA256_HEX_PATTERN = re.compile(r"^[0-9a-fA-F]{64}$")


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

    # CWE-354 Fix: Validate the format of the expected hash.
    # The expected SHA256 hash retrieved from the metadata_url must be
    # a string of 64 hexadecimal characters. If it's not, the validation
    # process itself is improper, as it relies on a malformed or invalid
    # expected value. This prevents comparison against non-hash data,
    # ensuring the integrity check is performed only with a valid hash format.
    if not isinstance(expected, str) or not SHA256_HEX_PATTERN.match(expected):
        return False

    return (
        hashlib.sha256(
            binary
        ).hexdigest()
        == expected
    )
