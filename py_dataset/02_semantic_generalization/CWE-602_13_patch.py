from typing import Any


# CWE-602 fix: Define server-side trusted prices.
# In a real application, this would come from a database, a secure configuration service, etc.
# For this exercise, a simple dictionary simulates this trusted source.
TRUSTED_PRODUCT_PRICES = {
    "P100": 100,  # Actual, server-side validated price for product P100
    "P200": 250,  # Example for another product
    # Add other products and their correct prices here
}


orders: list[dict[str, Any]] = []


def save_order(product_id: str, quantity: int, total_price: int) -> dict[str, Any]:
    order = {
        "product_id": product_id,
        "quantity": quantity,
        "total_price": total_price,
    }
    orders.append(order)
    return order


def create_order(request_json: dict[str, Any]) -> dict[str, Any]:
    product_id = request_json["product_id"]
    quantity = int(request_json["quantity"])
    
    # CWE-602 fix: Do not trust `unit_price` from client input.
    # Retrieve the authoritative `unit_price` from a trusted, server-side source.
    # If `product_id` is not found in TRUSTED_PRODUCT_PRICES, this will raise a KeyError,
    # similar to how accessing a non-existent key in `request_json` would behave.
    # This ensures that only server-validated prices are used for calculations.
    unit_price = TRUSTED_PRODUCT_PRICES[product_id]
    
    total_price = unit_price * quantity

    return save_order(product_id, quantity, total_price)


def main():
    manipulated_request = {
        "product_id": "P100",
        "quantity": 2,
        "unit_price": 1, # This value is now ignored by the patched code
    }

    print(create_order(manipulated_request))


if __name__ == "__main__":
    main()
