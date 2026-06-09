from dataclasses import dataclass

# These repositories are assumed to exist in the application context.
# We provide minimal definitions to make the code syntactically complete.
class ProductRepository:
    # In a real application, this would fetch product data from a database or service.
    # For demonstration, we use a simple in-memory dictionary.
    _products = {
        "product_A": {"price": 100},
        "product_B": {"price": 250},
        "product_C": {"price": 15},
    }

    def get_price(self, product_id: str) -> int:
        product_info = self._products.get(product_id)
        if product_info is None:
            raise ValueError(f"Product {product_id} not found.")
        return product_info["price"]

class OrderRepository:
    # In a real application, this would interact with a database.
    # For demonstration, we use a simple in-memory list.
    _orders = []
    _next_order_id = 1

    def insert(self, product_id: str, quantity: int, total: int) -> dict:
        order_data = {
            "order_id": self._next_order_id,
            "product_id": product_id,
            "quantity": quantity,
            "total": total,
            "status": "pending"
        }
        self._orders.append(order_data)
        self._next_order_id += 1
        return order_data

# Instantiate repositories as they would likely be used in a real application
# (e.g., as singletons or through dependency injection).
product_repository = ProductRepository()
order_repository = OrderRepository()

@dataclass(frozen=True)
class CheckoutCommand:
    product_id: str
    quantity: int
    displayed_price: int

class CheckoutService:
    def execute(self, command: CheckoutCommand) -> dict:
        # CWE-602 Fix: Do not rely on client-supplied 'displayed_price' for calculation.
        # Instead, fetch the authoritative price from a trusted server-side source.
        actual_price = product_repository.get_price(command.product_id)
        
        total = actual_price * command.quantity
        return order_repository.insert(command.product_id, command.quantity, total)
