from urllib.parse import unquote

async def access_middleware(scope, receive, send):
    raw = scope["raw_path"].decode("ascii")
    
    # CWE-647 fix: Perform the security check on the decoded path
    # to prevent bypasses using URL-encoded characters.
    # The path should be normalized (unquoted and redundant slashes removed)
    # before performing security-sensitive comparisons.
    normalized_path = unquote(raw).replace("//", "/")

    if normalized_path.startswith("/staff") and not scope["user"].is_staff:
        await send_forbidden(send)
        return
    
    scope["path"] = normalized_path
    await app(scope, receive, send)
