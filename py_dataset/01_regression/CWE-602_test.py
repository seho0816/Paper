def create_order(payload: dict) -> dict:
    product_id = payload['product_id']
    quantity = int(payload['quantity'])
    unit_price = int(payload['unit_price'])
    return order_repository.save({
        'product_id': product_id,
        'quantity': quantity,
        'total': unit_price * quantity,
    })
