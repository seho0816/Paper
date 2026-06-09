from dataclasses import dataclass
import ipaddress


@dataclass(frozen=True)
class AdminRequest:
    remote_address: str
    operation: str


class AdminGateway:
    def dispatch(
        self,
        request: AdminRequest,
    ):
        try:
            # CWE-291 Trust Boundary Violation:
            # Ensure that the remote_address is a syntactically valid IP address.
            # This helps to establish a basic level of trust for the format of the
            # address before it's used for access control decisions, preventing
            # potential bypasses or errors from malformed input that might
            # otherwise be considered trusted.
            ipaddress.ip_address(request.remote_address)
        except ValueError:
            raise PermissionError("remote address format is invalid")

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
