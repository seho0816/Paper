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
        # The validated_path has already been decoded once by GatewayValidator.
        # Decoding it again here would constitute a CWE-174 (double decoding) vulnerability,
        # potentially allowing bypass of security checks performed on the singly-decoded path.
        # Therefore, the second unquote call is removed, and the already validated
        # and once-decoded path is used directly.
        # final_path = unquote(
        #     validated_path
        # )

        return dispatch_route(
            validated_path
        )
