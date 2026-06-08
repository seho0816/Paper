class BillingClient:
    def charge(self, order_id: str, amount: int) -> dict[str, int | str]:
        return {
            "order_id": order_id,
            "amount": amount,
        }


def create_charge(order_id: str, amount: int) -> dict[str, int | str]:
    client = BillingClient()
    return client.charge(order_id, amount)
