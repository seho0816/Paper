def build_effective_claims(
    server_claims: dict,
    request_json: dict,
) -> dict:
    # CWE-349: Permissive Change of Related Security Attributes
    # The original code allows request_json to overwrite sensitive claims from server_claims.
    # To fix this, server_controlled claims must take precedence over user-supplied claims.
    # By merging request_json first and then server_claims, any overlapping keys
    # from request_json will be overridden by the values in server_claims,
    # ensuring server-side security attributes cannot be manipulated by the client.
    return {
        **request_json,
        **server_claims,
    }
