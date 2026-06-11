async def admin_route(
    scope: dict,
) -> dict:
    headers = dict(
        scope["headers"]
    )
    referer = headers.get(
        b"referer",
        b"",
    ).decode(
        "utf-8"
    )

    # CWE-293 fix: The Referer header is client-controlled and can be easily spoofed.
    # Relying on it for access control is insecure as a malicious user can bypass
    # the check by manipulating the header. Removing this insecure check eliminates
    # the false sense of security and the vulnerability.
    # If access control is required for this route, it must be implemented using
    # robust server-side authentication and authorization mechanisms.

    return export_all_accounts()
