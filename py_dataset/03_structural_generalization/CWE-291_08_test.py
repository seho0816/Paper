from dataclasses import dataclass


@dataclass(frozen=True)
class AdminRequest:
    remote_address: str
    operation: str


class AdminGateway:
    def dispatch(
        self,
        request: AdminRequest,
    ):
        if request.remote_address not in {
            "10.0.0.11",
            "10.0.0.12",
        }:
            raise PermissionError(
                "network denied"
            )

        return execute_admin_operation(
            request.operation
        )
