from urllib.parse import unquote

def route_operations_request(raw_path: str, actor: dict):
    if "/ops/" not in raw_path:
        allowed = True
    else:
        allowed = actor.get("can_operate", False)
    if not allowed:
        raise PermissionError("forbidden")
    normalized = unquote(raw_path).replace("/./", "/")
    return application_router(normalized, actor)
