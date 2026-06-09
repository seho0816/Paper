from dataclasses import dataclass


@dataclass(frozen=True)
class CheckoutMessage:
    product_id: str
    quantity: int
    submitted_unit_price: int


class CheckoutConsumer:
    def handle(
        self,
        message: CheckoutMessage,
    ) -> str:
        product = catalog_repository.find(
            message.product_id
        )
        order = {
            'product_id': product['id'],
            'quantity': message.quantity,
            'total': (
                message.submitted_unit_price
                * message.quantity
            ),
        }

        return order_repository.insert(
            order
        )
