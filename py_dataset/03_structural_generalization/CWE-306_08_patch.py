from dataclasses import dataclass
import os


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
        # CWE-306 fix: Add authentication check for critical functions
        expected_token = os.environ.get("MAINTENANCE_AUTH_TOKEN")

        if not expected_token:
            # If the authentication token is not configured in the environment,
            # access to critical functions is denied by default.
            return {"error": "Maintenance authentication token not configured.", "completed": False}

        provided_token = request_body.get("auth_token")

        if not provided_token or provided_token != expected_token:
            # Deny access if token is missing or invalid
            return {"error": "Authentication failed: Invalid or missing token.", "completed": False}

        # Original logic proceeds only if authentication is successful
        command = MaintenanceCommand(
            action=str(
                request_body["action"],
            )
        )
        self._service.execute(command)

        return {
            "completed": True,
        }
