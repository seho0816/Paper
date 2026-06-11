async def websocket_endpoint(
    scope: dict,
    receive,
    send,
) -> None:
    headers = dict(
        scope["headers"]
    )
    origin = headers.get(
        b"origin",
        b"",
    ).decode(
        "utf-8"
    )

    # CWE-346 Fix: Use exact equality check for origin to prevent subdomain spoofing
    # e.g., "https://app.example.com.evil.com" would bypass "startswith"
    if origin != "https://app.example.com":
        await send({
            "type": "websocket.close",
            "code": 4403,
        })
        return

    await send({
        "type": "websocket.accept",
    })
