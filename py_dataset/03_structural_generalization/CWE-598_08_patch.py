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
        # CWE-598: Information Exposure Through Query Strings in GET Request
        # Sensitive information like session_token should not be exposed in URL query parameters.
        # Removing the session_token from the URL query string addresses this vulnerability.
        return (
            request.origin
            + "/resume"
        )
