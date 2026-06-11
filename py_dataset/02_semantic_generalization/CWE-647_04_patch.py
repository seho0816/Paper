import posixpath
from urllib.parse import unquote

def proxy_request(environ: dict, actor: dict):
    forwarded = environ["HTTP_X_ORIGINAL_URI"]
    routed_path = posixpath.normpath(unquote(forwarded))
    if routed_path.startswith("/private/") and actor["tier"] != "operator":
        raise PermissionError("denied")
    return upstream.handle(routed_path, actor)
