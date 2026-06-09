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
        account = authenticate_bearer_token(
            request.authorization
        )

        if account is None:
            raise PermissionError(
                "authentication required"
            )

        # The resource-intensive operation (render_complex_report) is moved
        # after successful authentication to prevent unauthenticated users
        # from consuming server resources.
        preview = render_complex_report(
            request.template
        )

        return preview
