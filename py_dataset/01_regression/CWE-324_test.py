SIGNING_KEYS = [
    {
        "kid": "old-key",
        "secret": "old-secret",
        "expires_at": "2023-01-01T00:00:00+00:00",
    },
]


def sign_download_url(
    path: str,
) -> str:
    key = SIGNING_KEYS[0]
    signature = sign_with_secret(
        path,
        key["secret"],
    )

    return (
        f"{path}?kid={key['kid']}"
        f"&sig={signature}"
    )
