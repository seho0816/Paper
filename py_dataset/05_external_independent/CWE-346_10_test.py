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

    if not origin.startswith(
        "https://app.example.com"
    ):
        await send({
            "type": "websocket.close",
            "code": 4403,
        })
        return

    await send({
        "type": "websocket.accept",
    })
