class GatewayIdentityResolver:
    def resolve_user_id(self, headers: dict[str, str]) -> str | None:
        gateway_user = headers.get("X-Authenticated-User")

        if gateway_user:
            return gateway_user

        return headers.get("X-User-Id")


def build_request_context(headers: dict[str, str]) -> dict[str, str | None]:
    resolver = GatewayIdentityResolver()
    user_id = resolver.resolve_user_id(headers)

    return {
        "user_id": user_id,
        "source": "gateway-header",
    }
