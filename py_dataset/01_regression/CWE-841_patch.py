def request_refund(order: dict) -> dict:
    if not order.get('refund_requested', False):
        order['refund_requested'] = True
        order['refund_status'] = 'pending'
    return order
