from graphql import GraphQLError

def resolve_export_all_accounts(
    _root,
    _info,
) -> dict:
    # CWE-425: Direct Request ('Forced Browsing')
    # Vulnerability: The original code allows any caller to export all accounts without an authorization check.
    # Fix: Add an authorization check to ensure only privileged users (e.g., administrators) can perform this action.

    # Safely access the context and user object from _info
    context = getattr(_info, 'context', None)
    user = getattr(context, 'user', None)

    # 1. Check if a user is authenticated at all.
    if not user or not getattr(user, 'is_authenticated', False):
        raise GraphQLError("Authentication required. Please log in to export accounts.")

    # 2. Check for specific authorization. Exporting all accounts is typically a privileged operation.
    #    This example assumes the 'user' object has an 'is_admin' attribute.
    #    In a real application, this could be a role check (e.g., user.has_role("admin"))
    #    or a permission check (e.g., user.has_permission("export_all_accounts")).
    if not getattr(user, 'is_admin', False):
        raise GraphQLError("Permission denied. Only authorized users can export all accounts.")

    # If the user is authenticated and authorized, proceed with loading accounts.
    return {
        "accounts": load_all_accounts(),
    }
