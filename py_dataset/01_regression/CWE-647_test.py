from urllib.parse import unquote

def dispatch(raw_path: str, actor: dict):
    if raw_path.startswith("/admin") and actor.get("role") != "admin":
        raise PermissionError("forbidden")
    canonical = unquote(raw_path).replace("//", "/")
    return application_router(canonical, actor)
