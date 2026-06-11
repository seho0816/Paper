import os


def can_access_admin(headers: dict) -> bool:
    # CWE-807 Mitigation: Reliance on Untrusted Input in a Security Decision
    # Instead of relying on a hardcoded, easily guessable string ('true'),
    # the function now checks against a secret value configured securely
    # via an environment variable. This ensures that only trusted callers
    # who know this secret, or an upstream system that sets this header
    # after proper authentication/authorization, can gain admin access.
    
    expected_secret = os.environ.get("ADMIN_ACCESS_SECRET")

    # If the expected secret is not configured, access should be denied by default
    # to prevent granting privileges due to misconfiguration.
    if not expected_secret:
        return False
        
    return headers.get('X-Admin') == expected_secret


def delete_user(user_id: str, headers: dict) -> None:
    if not can_access_admin(headers):
        raise PermissionError('admin only')
    remove_user(user_id)
