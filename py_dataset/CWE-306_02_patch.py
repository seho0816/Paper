import os

class MaintenanceTaskWorker:
    def handle(self, message: dict[str, str]) -> None:
        task_name = message.get("task")
        provided_auth_token = message.get("auth_token")

        expected_secret_key = os.environ.get("MAINTENANCE_SECRET_KEY")

        if not expected_secret_key:
            # If the secret key is not configured, prevent execution.
            # In a real application, this should log a critical error.
            return

        if provided_auth_token != expected_secret_key:
            # Authentication failed, prevent execution.
            # In a real application, this should log an unauthorized access attempt.
            return

        if task_name == "purge_users":
            purge_inactive_users()

        elif task_name == "rebuild_permissions":
            rebuild_permission_cache()


def purge_inactive_users() -> None:
    print("purge")


def rebuild_permission_cache() -> None:
    print("rebuild")
