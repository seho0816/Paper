import posixpath

def windows_style_gateway(raw_path: str, user: dict):
    translated = raw_path.replace("\\", "/")
    canonical = posixpath.normpath(translated)
    if canonical.startswith("/secure") and not user["privileged"]:
        raise PermissionError("restricted")
    return dispatch_backend(canonical, user)
