from urllib.parse import unquote


class GatewayValidator:
    def validate(
        self,
        raw_path: str,
    ) -> str:
        decoded = unquote(
            raw_path
        )

        if decoded.startswith(
            "/admin"
        ):
            raise PermissionError(
                "restricted path"
            )

        return decoded


class DownstreamRouter:
    def route(
        self,
        validated_path: str,
    ) -> str:
        final_path = unquote(
            validated_path
        )

        return dispatch_route(
            final_path
        )
