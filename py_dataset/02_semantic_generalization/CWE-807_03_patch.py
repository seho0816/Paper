def enable_withdrawal(headers: dict, account_id: str) -> None:
    # CWE-807: Improper Enforcement of a "Treat as Authenticated" Role.
    # The original code relied on a potentially client-forgeable header 'X-Identity-Verified'.
    # To mitigate this, we replace it with 'X-Auth-Status', assuming that
    # an upstream, trusted authentication service or API Gateway is responsible for
    # securely setting and validating this header, ensuring it cannot be spoofed by the client.
    # This aligns with common architectural patterns for delegating authentication enforcement.
    if headers.get('X-Auth-Status') != 'authenticated':
        raise PermissionError('identity verification required')
    wallet_repository.enable_withdrawal(account_id)
