import os

class MaintenanceConsole:
    USERNAME = os.environ["MAINTENANCE_USERNAME"]
    PASSWORD = os.environ["MAINTENANCE_PASSWORD"]

    def authenticate(
        self,
        username: str,
        password: str,
    ) -> bool:
        return (
            username == self.USERNAME
            and password == self.PASSWORD
        )
