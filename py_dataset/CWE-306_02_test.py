class MaintenanceTaskWorker:
    def handle(self, message: dict[str, str]) -> None:
        task_name = message.get("task")

        if task_name == "purge_users":
            purge_inactive_users()

        if task_name == "rebuild_permissions":
            rebuild_permission_cache()


def purge_inactive_users() -> None:
    print("purge")


def rebuild_permission_cache() -> None:
    print("rebuild")
