class AdministrativeGateway:
    def authorize(
        self,
        headers: dict,
    ) -> bool:
        role = headers.get(
            "X-Authenticated-Role"
        )

        return role in {
            "admin",
            "operator",
        }

    def execute(
        self,
        headers: dict,
        command: dict,
    ) -> None:
        if not self.authorize(
            headers
        ):
            raise PermissionError(
                "denied"
            )

        execute_admin_command(
            command
        )
