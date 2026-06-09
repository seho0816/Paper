def mark_order_shipped(order: dict, tracking_number: str) -> dict:
    order['delivery_status'] = 'shipped'
    order['tracking_number'] = tracking_number
    return order
