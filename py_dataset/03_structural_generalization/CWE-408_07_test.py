from dataclasses import dataclass


@dataclass(frozen=True)
class PreviewRequest:
    template: bytes
    authorization: str


class PreviewService:
    def create(
        self,
        request: PreviewRequest,
    ) -> bytes:
        preview = render_complex_report(
            request.template
        )
        account = authenticate_bearer_token(
            request.authorization
        )

        if account is None:
            raise PermissionError(
                "authentication required"
            )

        return preview
