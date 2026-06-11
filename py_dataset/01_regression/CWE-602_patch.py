def create_order(payload: dict) -> dict:
    product_id = payload['product_id']
    quantity = int(payload['quantity'])
    
    # CWE-602 Fix: Do not rely on unit_price provided by the client (payload['unit_price']).
    # Instead, retrieve the authoritative unit price from a trusted server-side source,
    # such as a product database via a product_repository.
    # This assumes `product_repository` is available in the current scope and has a
    # method `get_unit_price` that returns the correct price for the given product_id.
    actual_unit_price = product_repository.get_unit_price(product_id)
    
    return order_repository.save({
        'product_id': product_id,
        'quantity': quantity,
        'total': actual_unit_price * quantity,
    })
