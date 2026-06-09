import socket


class AdministrativeGateway:
    def authorize(
        self,
        remote_address: str,
    ) -> bool:
        hostname = socket.gethostbyaddr(
            remote_address
        )[0]

        return hostname.endswith(
            ".management.example"
        )

    def execute(
        self,
        remote_address: str,
        operation: str,
    ):
        if not self.authorize(
            remote_address
        ):
            raise PermissionError(
                "access denied"
            )

        return execute_admin_operation(
            operation
        )
