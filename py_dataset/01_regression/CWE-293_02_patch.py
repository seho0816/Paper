import urllib.parse

def delete_api_key(
    headers: dict,
    key_id: str,
) -> None:
    referer = headers.get(
        "Referer",
        "",
    )

    parsed_referer = urllib.parse.urlparse(referer)
    hostname = parsed_referer.hostname

    if not hostname or \
       not (hostname == "dashboard.example.com" or hostname.endswith(".dashboard.example.com")):
        raise PermissionError(
            "invalid request"
        )

    api_key_repository.delete(
        key_id
    )
