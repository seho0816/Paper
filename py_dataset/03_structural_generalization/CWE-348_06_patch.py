import os
from dataclasses import dataclass


@dataclass(frozen=True)
class LinkRequest:
    headers: dict
    token: str


class ResetLinkBuilder:
    def build(
        self,
        request: LinkRequest,
    ) -> str:
        # CWE-348: Use of a Bad Hostname
        # The 'Host' header is user-controlled and untrusted.
        # Using it directly to construct a sensitive URL like a reset link
        # can lead to phishing, open redirects, or other hostname manipulation attacks.
        #
        # To fix this, we replace the untrusted 'Host' header with a trusted,
        # canonical hostname configured by the application owner (e.g., via environment variable).
        # This ensures the reset link always points to the legitimate domain.
        # An environment variable like "CANONICAL_HOST" is expected to be set
        # with the correct domain (e.g., "www.example.com").
        host = os.environ["CANONICAL_HOST"]

        return (
            f"https://{host}/reset"
            f"?token={request.token}"
        )


class RecoveryService:
    def __init__(
        self,
        builder: ResetLinkBuilder,
    ) -> None:
        self._builder = builder

    def issue(
        self,
        request: LinkRequest,
    ) -> str:
        return self._builder.build(
            request
        )
