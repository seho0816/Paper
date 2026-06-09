import hmac
import hashlib
import os
from typing import Any


# As per rule 7, the secret key must be loaded from an environment variable.
# If 'ROLE_SECRET_KEY' is not set, a KeyError will be raised, which is acceptable
# for ensuring proper environment configuration in a secure application.
SECRET_KEY = os.environ["ROLE_SECRET_KEY"].encode('utf-8')


def load_admin_dashboard() -> dict[str, Any]:
    return {
        "total_users": 100,
        "revenue": 500000,
    }


def get_role_from_cookie(cookies: dict[str, str]) -> str:
    role_cookie_value = cookies.get("role")
    if not role_cookie_value:
        return "guest"

    # Expected format for a securely signed role: "role_name.signature"
    parts = role_cookie_value.split('.', 1)
    if len(parts) != 2:
        # If the cookie value is not in the expected format (e.g., plain "admin"),
        # it is considered invalid and untrusted.
        return "guest"

    role_name = parts[0]
    provided_signature = parts[1]

    # Compute the expected signature for the role name using a secret key.
    message = role_name.encode('utf-8')
    computed_signature = hmac.new(SECRET_KEY, message, hashlib.sha256).hexdigest()

    # Compare the provided signature with the computed signature using a
    # timing-attack safe comparison to prevent information leakage.
    if hmac.compare_digest(computed_signature, provided_signature):
        # If the signature is valid, the role name is trusted.
        return role_name
    else:
        # If the signature is invalid, the role is not trusted and
        # defaults to "guest".
        return "guest"


def view_admin_dashboard(cookies: dict[str, str]) -> dict[str, Any]:
    role = get_role_from_cookie(cookies)

    if role != "admin":
        raise PermissionError("admin only")

    return load_admin_dashboard()


def main():
    # This dictionary simulates a client-manipulated cookie where
    # the 'role' is set to "admin" without proper server-side signing.
    # After the fix, such a plain "admin" role without a valid signature
    # will no longer grant access, preventing authorization bypass.
    manipulated_cookies = {
        "role": "admin",
    }

    try:
        print(view_admin_dashboard(manipulated_cookies))
    except PermissionError as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    main()
