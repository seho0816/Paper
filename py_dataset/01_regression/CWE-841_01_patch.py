def confirm_email_change(user: dict, new_email: str) -> dict:
    # CWE-841: Improper Enforcement of an Essential Condition
    # The essential condition for confirming an email change is that the
    # new_email must match a previously initiated and validated pending change
    # for this specific user. Without this check, an attacker or a stale
    # request could lead to an unauthorized email update.
    # We assume 'pending_email_change' in the user dictionary holds the
    # email that was initiated and verified (e.g., via a token flow).
    if user.get('pending_email_change') == new_email:
        user['email'] = new_email
        user['email_verified'] = True
        # After successful confirmation, the pending state should be cleared.
        if 'pending_email_change' in user:
            del user['pending_email_change']
    # If the essential condition (matching pending_email_change) is not met,
    # the function returns the user object without making any changes,
    # thereby preventing an unverified or unauthorized email update.
    return user
