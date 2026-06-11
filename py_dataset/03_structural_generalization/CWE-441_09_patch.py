from dataclasses import dataclass


@dataclass(frozen=True)
class MaintenanceRequest:
    action: str
    resource_id: str


class MaintenanceGateway:
    # Define a whitelist of allowed maintenance actions.
    # In a real application, this list would be carefully curated
    # to include only the specific, authorized operations that
    # this gateway is permitted to trigger via the admin API.
    _ALLOWED_ACTIONS = {
        "reboot_server",
        "shutdown_service",
        "clear_cache",
        "update_configuration",
        "backup_data",
        "monitor_health",
    }

    def __init__(
        self,
        admin_api,
    ) -> None:
        self._admin_api = admin_api

    def execute(
        self,
        request: MaintenanceRequest,
    ):
        # CWE-441: Unintended Proxy/Intermediary
        # The 'action' field from the MaintenanceRequest is used directly
        # to call a privileged API. Without validation, an attacker could
        # potentially craft a request to perform unintended or unauthorized
        # administrative actions.
        #
        # Fix: Validate the requested action against a predefined whitelist
        # of allowed actions. If the action is not in the whitelist,
        # it is considered an unauthorized or invalid action, and an error
        # is raised to prevent execution.
        if request.action not in self._ALLOWED_ACTIONS:
            raise ValueError(f"Unauthorized or invalid maintenance action: {request.action}")

        return self._admin_api.call(
            request.action,
            request.resource_id,
            credentials=ADMIN_CREDENTIALS,
        )
