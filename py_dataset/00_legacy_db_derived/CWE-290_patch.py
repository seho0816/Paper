class GatewayIdentityResolver:
    def resolve_user_id(self, headers: dict[str, str]) -> str | None:
        # CWE-290: Authentication Bypass by Spoofing.
        # The 'X-Authenticated-User' header is often intended to be set by a trusted
        # upstream authentication gateway. If an untrusted client can set this header,
        # it could bypass authentication mechanisms.
        # To mitigate this, we remove reliance on 'X-Authenticated-User' if it can be
        # spoofed by clients. The application should only trust authentication information
        # that has been verified through a secure process, not directly from client headers
        # that imply prior authentication by an external trusted entity.
        # This patch ensures that the application does not implicitly trust a potentially
        # spoofed 'X-Authenticated-User' header.
        
        # The 'X-User-Id' header is retained as a less privileged identifier,
        # typically client-provided or for unauthenticated scenarios, which may be
        # validated or further processed by other parts of the system.
        return headers.get("X-User-Id")


def build_request_context(headers: dict[str, str]) -> dict[str, str | None]:
    resolver = GatewayIdentityResolver()
    user_id = resolver.resolve_user_id(headers)

    return {
        "user_id": user_id,
        "source": "gateway-header",
    }
