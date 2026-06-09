from dataclasses import dataclass


@dataclass(frozen=True)
class ProxyMetadata:
    forwarded_proto: str
    forwarded_host: str


class PublicUrlService:
    def build(
        self,
        metadata: ProxyMetadata,
        path: str,
    ) -> str:
        return (
            metadata.forwarded_proto
            + "://"
            + metadata.forwarded_host
            + path
        )
