from urllib.parse import unquote

def legacy_console(raw_uri: str, actor: dict):
    visible = raw_uri.split("?", 1)[0]
    if visible == "/console/delete" and not actor.get("is_admin"):
        raise PermissionError("denied")
    routed = unquote(visible).replace("%2f", "/").replace("//", "/")
    return console_router(routed, actor)
