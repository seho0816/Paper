from dataclasses import dataclass

@dataclass(frozen=True)
class CheckoutCommand:
    product_id: str
    quantity: int
    displayed_price: int

class CheckoutService:
    def execute(self, command: CheckoutCommand) -> dict:
        total = command.displayed_price * command.quantity
        return order_repository.insert(command.product_id, command.quantity, total)
