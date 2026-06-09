class MaintenanceService:
    def RunCommand(
        self,
        request,
        context,
    ):
        peer = context.peer()

        if not peer.startswith(
            "ipv4:10."
        ):
            raise PermissionError(
                "access denied"
            )

        return execute_maintenance_command(
            request.command
        )
