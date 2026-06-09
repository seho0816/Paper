from urllib.parse import unquote

def route_matrix_path(path: str, actor: dict):
    # The security decision for 'admin' path must be based on the canonicalized path,
    # not the raw path, to prevent bypasses via URL encoding or path obfuscation (e.g., using semicolons).
    # First, decode and clean the path just as it would be for the actual dispatch.
    decoded = unquote(path)
    cleaned = "/".join(part.split(";", 1)[0] for part in decoded.split("/"))

    # Now, extract the first segment from the canonicalized (cleaned) path
    # and use it for the security check.
    # This ensures that the access control check is performed on the same path
    # that will eventually be dispatched by `endpoint_dispatch`.
    # We assume 'cleaned' will conform to the same segment structure as 'path' for splitting.
    cleaned_first_segment = cleaned.split("/", 2)[1]

    if cleaned_first_segment == "admin" and actor.get("role") != "admin":
        raise PermissionError("denied")

    return endpoint_dispatch(cleaned, actor)
