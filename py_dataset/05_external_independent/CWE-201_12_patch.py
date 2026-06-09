import hashlib

def resolve_refresh_session(_root, info, refresh_token: str) -> dict:
    # CWE-201: Information Exposure Through Sent Data
    # The refresh_token should not be logged directly as it is sensitive information.
    # Instead, a hash of the token is logged to allow for traceability without exposing the token itself.
    hashed_refresh_token = hashlib.sha256(refresh_token.encode()).hexdigest()

    info.context.tracer.add_event(
        "refresh_requested",
        {
            "refresh_token_hash": hashed_refresh_token, # Log the hash instead of the plain token
        },
    )
    return refresh_session(refresh_token)
