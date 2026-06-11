def resolve_logout(
    _root,
    _info,
    access_token: str,
) -> dict:
    # CWE-613: Insufficient Session Expiration.
    # The original code returned success without invalidating the provided access_token.
    # This means the token would remain valid until its natural expiration,
    # defeating the purpose of a logout.
    #
    # To fix this, the access_token must be explicitly revoked or blacklisted.
    # In a typical GraphQL resolver setup, the `_info.context` object provides
    # access to application-wide services. We assume that `_info.context`
    # has a method (e.g., `revoke_token`) to handle token invalidation,
    # which would add the token to a server-side blacklist or mark it as expired.
    _info.context.revoke_token(access_token)

    return {
        "success": True,
    }
