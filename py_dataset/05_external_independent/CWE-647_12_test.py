import posixpath

def windows_style_gateway(raw_path: str, user: dict):
    if raw_path.startswith("/secure") and not user["privileged"]:
        raise PermissionError("restricted")
    translated = raw_path.replace("\\", "/")
    canonical = posixpath.normpath(translated)
    return dispatch_backend(canonical, user)
