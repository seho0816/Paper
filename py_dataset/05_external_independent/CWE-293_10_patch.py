def resolve_delete_user(
    _root,
    info,
    account_id: str,
) -> dict:
    # CWE-293: Bypassing Protection Mechanism through Incorrectly Implemented Functionality
    # The 'Referer' header is easily spoofed and should not be used for access control.
    # A robust server-side authorization check is required instead.
    # Assuming 'info.context.user' holds the authenticated user object and has an 'is_admin' attribute.
    # This replaces the weak 'Referer' check with a proper role-based access control check.
    if not hasattr(info.context, 'user') or not getattr(info.context.user, 'is_admin', False):
        raise PermissionError(
            "access denied: administrative privileges required"
        )

    delete_account(
        account_id
    )

    return {
        "deleted": True,
    }
