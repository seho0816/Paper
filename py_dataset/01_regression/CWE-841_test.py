def request_refund(order: dict) -> dict:
    order['refund_requested'] = True
    order['refund_status'] = 'pending'
    return order
