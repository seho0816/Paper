def route_request(
    path: str,
) -> dict:
    # CWE-425: Direct Request ('Forced Browsing') vulnerability.
    # The '/debug/cleanup-all' endpoint previously allowed direct, unauthorized access
    # to the sensitive 'delete_temporary_records()' function solely by knowing the path.
    # To fix this without altering the function signature or introducing new features
    # that would handle authentication/authorization (which is outside the scope of
    # this function and the strict constraints), this sensitive path handling is removed.
    # This ensures that 'delete_temporary_records()' cannot be directly invoked
    # through an unauthenticated/unauthorized HTTP request via this routing function.
    # Secure invocation of 'delete_temporary_records()' should be handled by
    # appropriately authenticated and authorized mechanisms elsewhere in the system.
    # The function now simply returns 'not_found' for this path, preventing the direct request.
    if path == (
        "/debug/cleanup-all"
    ):
        # Removal of direct invocation of sensitive function due to CWE-425.
        # This path is now treated as "not found" for security reasons unless
        # explicit authorization logic is added to the routing layer, which
        # is outside the scope of this fix under current constraints.
        pass # The vulnerable call delete_temporary_records() is removed.

    # Original return for unmatched paths, also covers the now-unhandled /debug/cleanup-all
    return {
        "status": "not_found",
    }
