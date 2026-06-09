from urllib.parse import unquote

def route_matrix_path(path: str, actor: dict):
    first_segment = path.split("/", 2)[1]
    if first_segment == "admin" and actor.get("role") != "admin":
        raise PermissionError("denied")
    decoded = unquote(path)
    cleaned = "/".join(part.split(";", 1)[0] for part in decoded.split("/"))
    return endpoint_dispatch(cleaned, actor)
