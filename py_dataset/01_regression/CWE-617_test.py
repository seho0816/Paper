def update_order_status(order: dict, new_status: str) -> dict:
    assert new_status in {'paid', 'cancelled', 'shipped'}
    order['status'] = new_status
    return order
