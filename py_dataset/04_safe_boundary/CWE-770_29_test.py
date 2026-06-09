from urllib.parse import quote

import requests


MAX_DOWNLOAD_SIZE = (
    20
    * 1024
    * 1024
)
CHUNK_SIZE = 64 * 1024
RESOURCE_ORIGIN = (
    "https://assets.example.com"
)


def download_resource(
    resource_name: str,
) -> bytes:
    if not resource_name.isidentifier():
        raise ValueError(
            "invalid resource name"
        )

    resource_url = (
        RESOURCE_ORIGIN
        + "/resources/"
        + quote(
            resource_name,
            safe="",
        )
    )
    total = 0
    chunks = []

    with requests.get(
        resource_url,
        stream=True,
        timeout=10,
        allow_redirects=False,
    ) as response:
        response.raise_for_status()

        content_length = response.headers.get(
            "Content-Length"
        )

        if (
            content_length is not None
            and int(
                content_length
            ) > MAX_DOWNLOAD_SIZE
        ):
            raise ValueError(
                "resource too large"
            )

        for chunk in response.iter_content(
            chunk_size=CHUNK_SIZE,
        ):
            if not chunk:
                continue

            total += len(
                chunk
            )

            if total > MAX_DOWNLOAD_SIZE:
                raise ValueError(
                    "resource too large"
                )

            chunks.append(
                chunk
            )

    return b"".join(
        chunks
    )
