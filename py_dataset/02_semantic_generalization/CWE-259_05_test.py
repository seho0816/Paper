class MaintenanceConsole:
    USERNAME = "maintenance"
    PASSWORD = "maint-2026"

    def authenticate(
        self,
        username: str,
        password: str,
    ) -> bool:
        return (
            username == self.USERNAME
            and password == self.PASSWORD
        )
