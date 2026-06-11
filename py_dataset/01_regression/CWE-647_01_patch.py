from urllib.parse import unquote_plus
import posixpath

def authorize_then_route(raw_path: str, actor: dict):
    # Step 1: Decode URL-encoded characters in the raw path.
    decoded_path = unquote_plus(raw_path)
    
    # Step 2: Normalize directory separators (e.g., convert '\' to '/')
    # This ensures consistency across different OS path styles before canonicalization.
    normalized_separators_path = decoded_path.replace("\\", "/")
    
    # Step 3: Canonicalize the path by resolving '..' and '.' components.
    # This is crucial to prevent path traversal vulnerabilities from bypassing security checks
    # that rely on path prefixes (e.g., '/internal').
    # The original CWE-647 vulnerability (Reliance on a Single Factor in a Security Decision)
    # arose because the security decision relied on the 'raw_path' string, which could be
    # misleading due to un-resolved path components like "../". An attacker could craft
    # a path like "/public/../internal/secret" that doesn't start with "/internal" on the
    # raw string, but resolves to an internal path.
    canonical = posixpath.normpath(normalized_separators_path)
    
    # If the canonical path resolves to '.', it means the original path was empty or resolved to current directory.
    # For web paths, it's generally expected to start with '/', so we ensure this if applicable.
    # However, posixpath.normpath already handles leading slashes correctly for most web path scenarios.
    # If original raw_path did not start with '/', and canonical remains non-absolute,
    # the startswith("/internal") check would still correctly apply to the relative path.
    
    # Apply the original security logic, but now on the fully canonicalized path.
    # This ensures that the 'startswith("/internal")' check is performed on the
    # true, resolved path, eliminating the reliance on an easily manipulable single factor.
    if not canonical.startswith("/internal") or actor.get("role") == "administrator":
        return application_router(canonical, actor)
    
    raise PermissionError("forbidden")
