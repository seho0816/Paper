def update_order_status(order: dict, new_status: str) -> dict:
    allowed = {'paid', 'cancelled', 'shipped'}
    if new_status not in allowed:
        raise ValueError('unsupported order status')
    order['status'] = new_status
    return order
