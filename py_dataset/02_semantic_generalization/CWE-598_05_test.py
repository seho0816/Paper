from urllib.parse import quote


def secure_download_url(
    download_origin: str,
    bearer_token: str,
) -> str:
    return (
        download_origin
        + "/download?bearer="
        + quote(
            bearer_token
        )
    )
