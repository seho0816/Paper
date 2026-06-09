from dataclasses import dataclass


@dataclass(frozen=True)
class BillingAddressCommand:
    customer_id: str
    address: str


class BillingRepository:
    def update_address(
        self,
        command: BillingAddressCommand,
    ) -> None:
        # `database` is an assumed global or injected dependency.
        database.execute(
            "UPDATE customers SET billing_address = ? WHERE id = ?",
            (command.address, command.customer_id),
        )


class BillingService:
    def __init__(self, repository: BillingRepository) -> None:
        self._repository = repository

    def update(
        self,
        session_id: str,
        payload: dict,
    ) -> None:
        # CWE-352 Fix: Add CSRF token validation.
        # It's assumed that `get_expected_csrf_token` is a globally available
        # or framework-provided function that retrieves the valid CSRF token
        # for the given session ID. This function is not defined here to
        # adhere to the "no new functionality" rule, as it's considered
        # part of the existing system context.
        # `lookup_customer_by_session` is also an assumed global function.

        csrf_token_from_payload = payload.get("csrf_token")
        
        # This function is assumed to exist in the application's context.
        expected_csrf_token = get_expected_csrf_token(session_id)

        if not csrf_token_from_payload or csrf_token_from_payload != expected_csrf_token:
            raise ValueError("Invalid CSRF token")

        customer_id = lookup_customer_by_session(session_id)
        self._repository.update_address(
            BillingAddressCommand(
                customer_id=customer_id,
                address=str(payload["address"]),
            )
        )
