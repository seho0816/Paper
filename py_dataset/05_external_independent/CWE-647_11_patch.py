from urllib.parse import unquote

def legacy_console(raw_uri: str, actor: dict):
    # Extract the path part before any query parameters.
    # This variable holds the raw, potentially encoded path segment.
    path_segment_before_query = raw_uri.split("?", 1)[0]

    # Normalize the path *before* any security-sensitive checks are performed.
    # This step decodes URL-encoded characters (like %2f for /) and collapses
    # multiple slashes, ensuring that all path representations are canonicalized.
    # This prevents attackers from bypassing security checks by encoding parts
    # of the path (e.g., using "/console%2fdelete" instead of "/console/delete")
    # which would otherwise evade checks on the raw string.
    # This addresses the timing issue related to CWE-647 by making the security
    # decision on the fully controlled and interpreted path.
    normalized_path = unquote(path_segment_before_query).replace("%2f", "/").replace("//", "/")

    # Perform the permission check on the canonical, normalized path.
    if normalized_path == "/console/delete" and not actor.get("is_admin"):
        raise PermissionError("denied")

    # Use the normalized path for routing to ensure consistency
    # with the path used for permission checks.
    routed = normalized_path
    return console_router(routed, actor)
