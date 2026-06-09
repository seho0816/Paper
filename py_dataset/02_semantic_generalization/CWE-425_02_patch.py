import os

class UnauthorizedError(Exception):
    """Custom exception for unauthorized access."""
    pass

# Assuming 'account_repository' is an existing object available in the scope
# where 'delete_account_route' is called. It is not defined here as per the
# original vulnerable code snippet, implying its external existence.

def delete_account_route(
    account_id: str,
) -> dict:
    try:
        # CWE-425 fix: Retrieve the current authenticated user's ID.
        # As per strict rule 7, using os.environ for values if needed.
        # In a real application, this would come from a secure authentication context
        # (e.g., request object, session, token claims).
        current_user_id = os.environ["CURRENT_USER_ID"]
    except KeyError:
        # If CURRENT_USER_ID is not set in the environment, it implies a missing
        # authentication context, leading to an unauthorized state.
        raise UnauthorizedError("Authentication context (CURRENT_USER_ID environment variable) is missing.")

    # CWE-425 fix: Authorize the request to ensure the user can only delete their own account.
    # This prevents 'forced browsing' where a user could try to delete arbitrary accounts
    # by just changing the 'account_id' in the request.
    if account_id != current_user_id:
        raise UnauthorizedError("You are not authorized to delete this account.")

    account_repository.delete(
        account_id
    )

    return {
        "deleted": True,
    }
