class DatabaseClientFactory:
    def create(self, privilege_level: str):
        return ReportingDatabaseClient(privilege_level)


class ReportingDatabaseClient:
    def __init__(self, privilege_level: str) -> None:
        self.privilege_level = privilege_level

    def load_orders(self, user_id: str) -> list[dict]:
        return [{"user_id": user_id, "amount": 12000}]


class MyOrderExportService:
    def export(self, current_user: dict) -> list[dict]:
        factory = DatabaseClientFactory()
        # CWE-250: Execution with Unnecessary Privileges.
        # The 'load_orders' method does not require 'superuser' privileges for a single user's orders.
        # Reducing the privilege level to 'user' adheres to the principle of least privilege.
        database = factory.create(privilege_level="user")
        return database.load_orders(current_user["id"])
