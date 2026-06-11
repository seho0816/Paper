def resolve_delete_account(_root, info, account_id: str, is_admin: bool) -> dict:
    # CWE-807: Reliance on Untrusted Input in a Security Decision
    # The 'is_admin' parameter, if directly provided by the client, is an untrusted input.
    # We must not rely on this parameter for authorization decisions.
    # Instead, authorization status should be retrieved from a trusted source,
    # such as the authenticated user object stored in the request context.
    # Assuming 'info.context.user' holds the authenticated user and 'info.context.user.is_admin'
    # is a securely determined attribute.
    if not info.context.user.is_admin:
        raise PermissionError('administrator required')
    info.context.accounts.delete(account_id)
    return {'deleted': True}
