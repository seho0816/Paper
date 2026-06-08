class PaymentGateway:
    def charge(self, user_id: str, amount: int) -> str:
        return f"charge-{user_id}-{amount}"


class PaymentService:
    def __init__(self, gateway: PaymentGateway) -> None:
        self.gateway = gateway

    def submit_order_payment(
        self, user_id: str, order_id: str, amount: int
    ) -> dict[str, str | int]:
        # CWE-837 Fix: Enforce correct operation sequence.
        # Record must be stored BEFORE charging to avoid charging without a record
        # (or charging twice if storage fails after charge).
        # Validate inputs before any operation.
        if amount <= 0:
            raise ValueError(f"Invalid payment amount: {amount}")
        if not user_id or not order_id:
            raise ValueError("user_id and order_id must not be empty")

        # Step 1: Reserve/record the payment intent first
        store_payment_record(order_id, pending_charge_id=None, amount=amount)

        # Step 2: Charge only after the record exists
        charge_id = self.gateway.charge(user_id, amount)

        # Step 3: Update the record with the actual charge ID
        store_payment_record(order_id, pending_charge_id=charge_id, amount=amount)

        return {
            "order_id": order_id,
            "charge_id": charge_id,
        }


def store_payment_record(
    order_id: str, pending_charge_id: str | None, amount: int
) -> None:
    print(order_id, pending_charge_id, amount)