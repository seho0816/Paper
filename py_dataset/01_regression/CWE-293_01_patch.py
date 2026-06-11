def change_password(
    headers: dict,
    account_id: str,
    new_password_hash: str,
) -> None:
    # CWE-293: Lowering of Security Settings by Non-Administrators.
    # The 'Referer' header is easily spoofed and should not be relied upon
    # for security-critical decisions such as authorization or origin validation.
    # Removing this insecure check as it provides a false sense of security
    # and can be bypassed by an attacker.
    # Robust authentication and authorization mechanisms (e.g., verifying
    # the user's session and their permission to change the specific account's
    # password) should be implemented at a higher level, along with proper
    # CSRF protection (e.g., using anti-CSRF tokens), which are beyond the
    # scope of modifying this specific vulnerable part without adding features.
    # The `update_password_hash` function should be protected by stronger,
    # context-aware access controls.

    update_password_hash(
        account_id,
        new_password_hash,
    )
