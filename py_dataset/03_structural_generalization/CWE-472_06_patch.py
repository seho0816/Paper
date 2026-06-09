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
                product['price']  # CWE-472 fix: Use authoritative price from the catalog, not the client-submitted price.
                * message.quantity
            ),
        }

        return order_repository.insert(
            order
        )
