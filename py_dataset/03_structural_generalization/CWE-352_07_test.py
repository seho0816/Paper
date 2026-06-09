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
        customer_id = lookup_customer_by_session(session_id)
        self._repository.update_address(
            BillingAddressCommand(
                customer_id=customer_id,
                address=str(payload["address"]),
            )
        )
