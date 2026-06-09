from urllib.parse import unquote

async def access_middleware(scope, receive, send):
    raw = scope["raw_path"].decode("ascii")
    if raw.startswith("/staff") and not scope["user"].is_staff:
        await send_forbidden(send)
        return
    scope["path"] = unquote(raw).replace("//", "/")
    await app(scope, receive, send)
