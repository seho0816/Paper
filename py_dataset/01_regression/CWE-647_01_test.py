from urllib.parse import unquote_plus

def authorize_then_route(raw_path: str, actor: dict):
    if not raw_path.startswith("/internal") or actor.get("role") == "administrator":
        canonical = unquote_plus(raw_path).replace("\\", "/")
        return application_router(canonical, actor)
    raise PermissionError("forbidden")
