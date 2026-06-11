ALLOWED_REFUND_DELIVERY_STATES = {
    'delivered',
}


def request_refund(order: dict) -> dict:
    if order.get('delivery_status') not in ALLOWED_REFUND_DELIVERY_STATES:
        raise ValueError('refund requires completed delivery')
    if order.get('refund_status') is not None:
        raise ValueError('refund already started')

    order['refund_requested'] = True
    order['refund_status'] = 'pending'
    return order

