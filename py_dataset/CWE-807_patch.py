from typing import Any


deleted_users: list[str] = []

# CWE-807 Fix: Introduce a trusted server-side source for authorization decisions.
# In a real application, this would be a secure session management system,
# a database of user roles, or cryptographically verified tokens (e.g., JWTs)
# with server-side validation. For this example, we use a simple set of trusted tokens.
TRUSTED_ADMIN_TOKENS = {"server_issued_admin_token_abcdef123456"}


def remove_user(user_id: str) -> None:
    deleted_users.append(user_id)


def can_access_admin(headers: dict[str, str]) -> bool:
    # CWE-807 Fix: Do not rely on untrusted client input (like "X-Admin" header)
    # for security-sensitive decisions. Instead, verify a server-issued and
    # validated token or session identifier.
    auth_header = headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.split(" ", 1)[1]
        # Simulate server-side token validation: check if the token is in our trusted list.
        # In a real system, this would involve cryptographic verification, database lookup, etc.
        return token in TRUSTED_ADMIN_TOKENS
    return False


def delete_user(user_id: str, headers: dict[str, str]) -> dict[str, Any]:
    if not can_access_admin(headers):
        raise PermissionError("admin only")

    remove_user(user_id)

    return {
        "deleted": user_id,
        "status": "ok",
    }


def main():
    # Original attacker headers that exploited the CWE-807 vulnerability.
    # After the fix, these headers will correctly result in a PermissionError.
    attacker_headers = {
        "X-Admin": "true",
    }

    try:
        print(delete_user("victim-user", attacker_headers))
    except PermissionError as e:
        # This error is now correctly raised, demonstrating the fix.
        print(f"Error: {e} - Access denied for untrusted 'X-Admin' header.")

    # Example of how a legitimate admin request would now succeed with a trusted token.
    # Note: This part is for demonstration of the fix's effect, not part of the original vulnerability.
    legitimate_admin_headers = {
        "Authorization": "Bearer server_issued_admin_token_abcdef123456",
    }
    print(delete_user("legitimate-admin-user", legitimate_admin_headers))


if __name__ == "__main__":
    main()
