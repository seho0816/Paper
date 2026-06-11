def resolve_current_user(
    _root,
    info,
) -> dict:
    username = None

    # CWE-290: Authentication Bypass by Spoofing an Authentication Info
    # The original code directly trusted the "X-User" header from the client,
    # which is easily spoofable. To fix this, we must obtain the user's
    # identity from a server-verified source, typically populated in the
    # context object by prior authentication middleware.
    # We assume 'info.context.user' holds the authenticated user object
    # if authentication was successful.
    
    authenticated_user = getattr(info.context, 'user', None)

    if authenticated_user and hasattr(authenticated_user, 'username') and authenticated_user.username:
        username = authenticated_user.username
    # If no authenticated user is found in the context, username remains None.
    # This ensures that user identity is derived from a trusted, server-verified
    # source and not from spoofable client input.

    return load_account(
        username
    )
