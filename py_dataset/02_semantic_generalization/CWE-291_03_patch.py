def allow_admin_action(
    headers: dict,
) -> bool:
    # CWE-291: Trust Boundary Violation.
    # The X-Forwarded-For header is user-controlled and can be easily spoofed by an attacker.
    # Relying on it directly for security-critical decisions (like admin access)
    # without proper validation (e.g., ensuring it comes from a trusted proxy and/or
    # using the actual direct peer IP from the server environment) is insecure.
    #
    # Since this function only has access to the 'headers' dictionary and no external
    # trusted source for the client IP, it cannot securely determine the client IP
    # from 'X-Forwarded-For' for a security decision.
    #
    # To precisely remove the CWE-291 vulnerability without introducing new ones
    # or changing the function's signature, the most secure approach is to
    # not trust the 'X-Forwarded-For' header for this security check.
    # By assigning an empty string, we ensure that no IP extracted from the
    # spoofable 'X-Forwarded-For' header can match the allowed admin IPs.
    # This effectively disables IP-based admin access through this function,
    # thereby eliminating the spoofing vulnerability.
    client_ip = ""

    return client_ip in {
        "10.1.1.5",
        "10.1.1.6",
    }
