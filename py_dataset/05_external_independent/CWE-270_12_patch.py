def resolve_impersonated_profile(_root, info, target_user_id: str) -> dict:
    # CWE-270: Privilege Mismanagement
    # The original code allows any user to arbitrarily set the current_user context
    # to any target_user_id with an 'admin' role, leading to unauthorized privilege escalation.
    #
    # Fix: Implement an authorization check to ensure that only users who already possess
    # administrative privileges can perform this impersonation.

    # Retrieve the details of the actual user making the request.
    current_caller_user = info.context.current_user

    # Check if the current caller user exists and has the 'admin' role.
    # If the caller is not an administrator, raise a PermissionError to prevent
    # unauthorized privilege elevation.
    if not current_caller_user or current_caller_user.get('role') != 'admin':
        raise PermissionError("Only administrators are authorized to resolve impersonated profiles.")

    # If the caller is an administrator, they are authorized to proceed.
    # The original logic of setting the current context for the target_user_id as 'admin'
    # is maintained as per the strict rules, as the vulnerability was the lack of access control.
    info.context.current_user = {'id': target_user_id, 'role': 'admin'}
    return info.context.accounts.load_private_profile(target_user_id)
