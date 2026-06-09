import posixpath
from urllib.parse import unquote

def proxy_request(environ: dict, actor: dict):
    forwarded = environ["HTTP_X_ORIGINAL_URI"]
    if forwarded.startswith("/private/") and actor["tier"] != "operator":
        raise PermissionError("denied")
    routed_path = posixpath.normpath(unquote(forwarded))
    return upstream.handle(routed_path, actor)
