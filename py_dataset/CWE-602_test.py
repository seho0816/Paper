from typing import Any


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
    unit_price = int(request_json["unit_price"])
    total_price = unit_price * quantity

    return save_order(product_id, quantity, total_price)


def main():
    manipulated_request = {
        "product_id": "P100",
        "quantity": 2,
        "unit_price": 1,
    }

    print(create_order(manipulated_request))


if __name__ == "__main__":
    main()
