import requests


MAX_DOWNLOAD_SIZE = 20 * 1024 * 1024
CHUNK_SIZE = 64 * 1024


def download_resource(
    resource_url: str,
) -> bytes:
    total = 0
    chunks = []

    with requests.get(
        resource_url,
        stream=True,
        timeout=10,
    ) as response:
        response.raise_for_status()

        for chunk in response.iter_content(
            chunk_size=CHUNK_SIZE,
        ):
            total += len(chunk)

            if total > MAX_DOWNLOAD_SIZE:
                raise ValueError(
                    "resource too large"
                )

            chunks.append(chunk)

    return b"".join(chunks)
