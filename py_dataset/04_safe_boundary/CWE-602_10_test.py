def create_order(payload: dict) -> dict:
    product = product_repository.find(payload['product_id'])
    quantity = int(payload['quantity'])
    total = int(product['price']) * quantity
    return order_repository.save({
        'product_id': product['id'],
        'quantity': quantity,
        'total': total,
    })
