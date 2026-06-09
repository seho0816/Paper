from dataclasses import dataclass


@dataclass(frozen=True)
class MaintenanceCommand:
    action: str


class MaintenanceService:
    def execute(
        self,
        command: MaintenanceCommand,
    ) -> None:
        if command.action == "reindex":
            rebuild_search_index()
        elif command.action == "purge-cache":
            clear_shared_cache()


class MaintenanceController:
    def __init__(
        self,
        service: MaintenanceService,
    ) -> None:
        self._service = service

    def handle(
        self,
        request_body: dict,
    ) -> dict:
        command = MaintenanceCommand(
            action=str(
                request_body["action"],
            )
        )
        self._service.execute(command)

        return {
            "completed": True,
        }
