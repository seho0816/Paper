from dataclasses import dataclass


@dataclass(frozen=True)
class SupportOperation:
    operation: str
    payload: dict


class SupportProxy:
    def __init__(
        self,
        internal_client,
    ) -> None:
        self._internal_client = internal_client

    def forward(
        self,
        request: SupportOperation,
    ):
        return self._internal_client.execute(
            operation=request.operation,
            payload=request.payload,
            service_token=SERVICE_TOKEN,
        )
