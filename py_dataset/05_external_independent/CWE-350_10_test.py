import socket


class OperationsService:
    def Run(
        self,
        request,
        context,
    ):
        peer_ip = extract_peer_ip(
            context.peer()
        )
        hostname = socket.gethostbyaddr(
            peer_ip
        )[0]

        if not hostname.endswith(
            ".operations.example"
        ):
            raise PermissionError(
                "access denied"
            )

        return run_operation(
            request.operation
        )
