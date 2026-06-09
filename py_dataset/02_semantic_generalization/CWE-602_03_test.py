def submit_mobile_order(body: dict) -> dict:
    items_total = sum(int(item['price']) * int(item['count']) for item in body['items'])
    shipping_fee = int(body['shipping_fee'])
    return payment_gateway.authorize(items_total + shipping_fee)
