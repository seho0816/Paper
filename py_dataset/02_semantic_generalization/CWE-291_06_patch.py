def resolve_request_role(
    remote_addr: str,
) -> str:
    # CWE-291 (Improper Privilege Management) is identified here.
    # Relying solely on `remote_addr` for privilege escalation (granting "admin" role)
    # is inherently insecure if `remote_addr` can be spoofed or represents an untrusted proxy.
    #
    # Given the strict rules to maintain the function signature and not add new features,
    # it's impossible for this function to securely determine an "admin" role based
    # *solely* on the provided `remote_addr` string without additional, trusted context
    # (e.g., request headers, a trusted proxy list, or an authenticated user identity).
    #
    # To mitigate the CWE-291 vulnerability within these constraints, the function
    # must not grant elevated privileges based on this potentially untrustworthy input.
    # Therefore, the conditional assignment of the "admin" role is removed.
    return "user"
