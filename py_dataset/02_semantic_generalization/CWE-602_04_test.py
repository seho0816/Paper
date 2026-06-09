def reserve_product(request_json: dict) -> bool:
    if not request_json.get('inventory_available'):
        return False
    inventory_repository.reserve(
        request_json['sku'],
        int(request_json['quantity']),
    )
    return True
