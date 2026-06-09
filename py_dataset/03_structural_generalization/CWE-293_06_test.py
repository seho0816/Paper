from dataclasses import dataclass


@dataclass(frozen=True)
class RequestMetadata:
    headers: dict


class RefererAuthorizationPolicy:
    def allow(
        self,
        metadata: RequestMetadata,
    ) -> bool:
        referer = metadata.headers.get(
            "Referer",
            "",
        )

        return referer.startswith(
            "https://admin.example.com/"
        )
