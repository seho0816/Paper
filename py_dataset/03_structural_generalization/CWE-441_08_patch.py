import os
from dataclasses import dataclass


@dataclass(frozen=True)
class SupportOperation:
    operation: str
    payload: dict


class SupportProxy:
    def __init__(
        self,
        internal_client,
    ) -> None:
        self._internal_client = internal_client
        # CWE-441 Mitigation: Whitelist allowed operations.
        # Load allowed operations from an environment variable.
        # This prevents the proxy from forwarding arbitrary operations.
        # If the environment variable is not set or is empty,
        # the proxy will not allow any operations by default, ensuring a secure-by-default posture.
        allowed_ops_str = os.environ.get("SUPPORT_PROXY_ALLOWED_OPERATIONS", "")
        if allowed_ops_str:
            self._allowed_operations = set(op.strip() for op in allowed_ops_str.split(',') if op.strip())
        else:
            self._allowed_operations = set() # No operations allowed if not configured.

    def forward(
        self,
        request: SupportOperation,
    ):
        # CWE-441 Mitigation: Check if the requested operation is in the allowed list.
        # If the operation is not explicitly permitted, reject the request to prevent unintended forwarding.
        if request.operation not in self._allowed_operations:
            raise ValueError(f"Operation '{request.operation}' is not permitted by this proxy.")

        # Assuming SERVICE_TOKEN is defined and accessible in the execution environment,
        # as it was part of the original vulnerable code.
        return self._internal_client.execute(
            operation=request.operation,
            payload=request.payload,
            service_token=SERVICE_TOKEN,
        )
