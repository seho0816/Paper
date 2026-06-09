from flask import request, session


def account_lookup():
    # Retrieve the authenticated user's ID from the session.
    # This assumes a proper authentication system populates 'user_id' in the session.
    authenticated_user_id = session.get("user_id")

    # CWE-235: Improper Handling of Missing Critical Step in Authentication.
    # In this context, the critical step is authorization: ensuring the user is
    # authorized to view the requested account_id.
    # To fix this, we enforce that only the authenticated user's own account_id
    # is ever passed to 'load_account' for a personal account lookup.
    
    if authenticated_user_id is None:
        # If no user is authenticated, they cannot access any specific account.
        # Passing None to 'load_account' should result in no account data
        # being returned or an appropriate error, preventing unauthenticated access
        # to arbitrary accounts via the 'account_id' parameter.
        account_id_to_load = None
    else:
        # For an authenticated user, we restrict the 'account_id' to their own.
        # This prevents Insecure Direct Object Reference (IDOR), where a user
        # might attempt to manipulate the 'account_id' parameter to access
        # another user's account data. The 'request.args.get("account_id")'
        # is ignored for authorization purposes and only the authenticated user's
        # ID is used.
        account_id_to_load = authenticated_user_id
    
    return load_account(
        account_id_to_load
    )
