import posixpath
from urllib.parse import unquote

def canonicalize_request_path(raw_path: str) -> str:
    decoded = unquote(raw_path).replace("\\", "/")
    canonical = posixpath.normpath("/" + decoded.lstrip("/"))
    return canonical

def authorize_and_route(raw_path: str, actor: dict):
    canonical = canonicalize_request_path(raw_path)
    if canonical.startswith("/admin") and actor.get("role") != "admin":
        raise PermissionError("forbidden")
    return application_router(canonical, actor)

