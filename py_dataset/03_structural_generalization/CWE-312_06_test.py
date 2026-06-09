from dataclasses import dataclass


@dataclass(frozen=True)
class IntegrationCredential:
    integration_id: str
    api_secret: str


class CredentialCache:
    def __init__(
        self,
        redis_client,
    ) -> None:
        self._redis = redis_client

    def put(
        self,
        credential: IntegrationCredential,
    ) -> None:
        self._redis.hset(
            f"integration:{credential.integration_id}",
            mapping={
                "api_secret": credential.api_secret,
            },
        )
