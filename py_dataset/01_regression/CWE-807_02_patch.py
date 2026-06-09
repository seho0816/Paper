def suspend_account(cookies: dict, target_account_id: str) -> None:
    # CWE-807: Reliance on Untrusted Inputs in a Security Decision
    # The 'role' attribute retrieved directly from client-sent cookies is an untrusted input.
    # A malicious user could easily modify their cookies to claim an 'administrator' role.
    # To fix this, the authorization decision must be based on a trusted, server-side verified role.

    # Assume that a trusted session identifier (e.g., 'session_id') is provided in the cookies
    # after successful authentication, and that 'account_repository' (or a similar authentication/session service)
    # can use this identifier to retrieve the user's actual, verified role from a server-side store.
    # This design pattern ensures that the role information is not modifiable by the client.
    session_identifier = cookies.get('session_id')

    if not session_identifier:
        # If no session identifier is present, the user is not authenticated or the session is invalid.
        raise PermissionError('authentication required: missing session identifier')

    # Retrieve the trusted user role from a server-side source using the session identifier.
    # This assumes 'account_repository' (or an accessible auth/session service) has a method
    # to look up the authentic role associated with the given session.
    # This call replaces the direct, untrusted access to `cookies.get('role')`.
    # We assume 'account_repository' is an object available in the current scope.
    trusted_role = account_repository.get_user_role_by_session_id(session_identifier)

    if trusted_role != 'administrator':
        raise PermissionError('administrator required')

    account_repository.suspend(target_account_id)
