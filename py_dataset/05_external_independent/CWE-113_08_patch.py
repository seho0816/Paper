from aiohttp import web


async def status(
    request: web.Request,
) -> web.Response:
    client_name = request.query.get(
        "client",
        "",
    )
    # CWE-113 fix: Neutralize CRLF sequences to prevent HTTP Response Splitting.
    # Remove carriage return and newline characters from the header value.
    sanitized_client_name = client_name.replace('\r', '').replace('\n', '')

    return web.Response(
        text="ok",
        headers={
            "X-Client-Name": sanitized_client_name,
        },
    )
