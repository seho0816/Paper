from dataclasses import dataclass

@dataclass
class OrderInput:
    product_id: str
    quantity: int

def calculate_total(payload: OrderInput) -> int:
    if payload.quantity < 1:
        raise ValueError("quantity must be positive")
    product = product_repository.get(payload.product_id)
    if product is None or not product.is_active:
        raise LookupError("product unavailable")
    return product.unit_price * payload.quantity
