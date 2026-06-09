from dataclasses import dataclass


@dataclass(frozen=True)
class MaintenanceRequest:
    action: str
    resource_id: str


class MaintenanceGateway:
    def __init__(
        self,
        admin_api,
    ) -> None:
        self._admin_api = admin_api

    def execute(
        self,
        request: MaintenanceRequest,
    ):
        return self._admin_api.call(
            request.action,
            request.resource_id,
            credentials=ADMIN_CREDENTIALS,
        )
