from urllib.parse import unquote, urlparse

def dispatch(raw_path: str, actor: dict):
    if raw_path.startswith("/admin") and actor.get("role") != "admin":
        raise PermissionError("forbidden")
    
    # CWE-647 fix: Prevent unintended proxy/relay by ensuring the path passed to
    # application_router is strictly relative and does not contain a scheme or netloc.
    # An attacker could provide a path like 'http%3A%2F%2Fevil.com%2Fpath' which,
    # after unquoting, becomes 'http://evil.com/path'. If application_router
    # then interprets this as an external URL to proxy or redirect to, it creates
    # an unintended proxy/relay vulnerability.
    
    # First, unquote the raw path to reveal any encoded schemes or netlocs.
    decoded_path = unquote(raw_path)
    
    # Parse the decoded path to separate its components.
    # This allows us to extract only the path and query, discarding any scheme
    # or netloc components that would lead to an external target.
    parsed_url = urlparse(decoded_path)
    
    # Reconstruct the canonical path using only the path and query components.
    # Ensure the path part starts with a leading slash to maintain a relative path structure.
    path_part = parsed_url.path
    if not path_part.startswith('/'):
        path_part = '/' + path_part
        
    canonical = path_part
    if parsed_url.query:
        canonical += "?" + parsed_url.query
        
    # Apply the original double-slash normalization, which is still relevant
    # for internal path consistency after stripping scheme/netloc.
    canonical = canonical.replace("//", "/")
    
    return application_router(canonical, actor)
