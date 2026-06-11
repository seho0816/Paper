def resolve_export_records(
    _root,
    info,
    required_role: str,
) -> list[dict]:
    actor = info.context.authenticated_user

    # CWE-863: Incorrect Authorization
    # The original check `actor["role"] != required_role` assumes 'role' is always a single string.
    # If actor["role"] could be a list of roles (e.g., `["admin", "user"]`),
    # the original comparison would incorrectly deny access if `required_role` was "user".
    # This fix normalizes the actor's role(s) into a list and checks for membership.
    
    actor_roles = actor["role"]
    
    # Ensure actor_roles is always a list for consistent membership checking
    if not isinstance(actor_roles, list):
        actor_roles = [actor_roles] # Convert single role string to a list containing that role

    if required_role not in actor_roles:
        raise PermissionError(
            "denied"
        )

    return export_sensitive_records()
