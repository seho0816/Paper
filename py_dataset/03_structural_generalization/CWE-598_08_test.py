from dataclasses import dataclass


@dataclass(frozen=True)
class ContinuationLink:
    origin: str
    session_token: str


class ContinuationLinkService:
    def build(
        self,
        request: ContinuationLink,
    ) -> str:
        return (
            request.origin
            + "/resume?session_token="
            + request.session_token
        )
