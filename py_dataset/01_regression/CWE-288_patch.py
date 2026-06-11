def login_with_backup_code(
    username: str,
    backup_code: str,
) -> dict | None:
    user = find_user_by_username(
        username
    )

    if user is None:
        return None

    if backup_code in user["backup_codes"]:
        # CWE-288: Authentication Bypass Using an Alternate Path or Channel
        # The backup code must be a one-time use credential.
        # Removing the code from the list after successful use prevents reuse.
        user["backup_codes"].remove(backup_code)
        # In a real-world application, changes to the user object (like removing backup codes)
        # would need to be persisted to a database or other storage mechanism.
        # However, per strict rules, we cannot add new function calls not present in the original code,
        # assuming that modifications to the 'user' dict are handled elsewhere or propagate implicitly.
        return create_session(
            user["id"]
        )

    return None
