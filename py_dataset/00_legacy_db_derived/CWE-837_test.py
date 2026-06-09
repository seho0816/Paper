class PaymentGateway:
    def charge(self, user_id: str, amount: int) -> str:
        return f"charge-{user_id}-{amount}"


class PaymentService:
    def __init__(self, gateway: PaymentGateway) -> None:
        self.gateway = gateway

    def submit_order_payment(self, user_id: str, order_id: str, amount: int) -> dict[str, str | int]:
        charge_id = self.gateway.charge(user_id, amount)
        store_payment_record(order_id, charge_id, amount)

        return {
            "order_id": order_id,
            "charge_id": charge_id,
        }


def store_payment_record(order_id: str, charge_id: str, amount: int) -> None:
    print(order_id, charge_id, amount)
