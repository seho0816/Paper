import urllib3


http = urllib3.PoolManager()


def relay_document(
    document_url: str,
) -> bytes:
    response = http.request(
        "GET",
        document_url,
        timeout=urllib3.Timeout(
            total=5,
        ),
        preload_content=True,
    )

    return response.data
