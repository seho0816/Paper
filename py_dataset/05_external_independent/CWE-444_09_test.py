async def proxy_request(
    scope: dict,
    receive,
    send_backend,
) -> None:
    body_parts = []

    while True:
        message = await receive()
        body_parts.append(
            message.get(
                "body",
                b"",
            )
        )

        if not message.get(
            "more_body",
            False,
        ):
            break

    await send_backend(
        headers=scope["headers"],
        body=b"".join(
            body_parts
        ),
    )
