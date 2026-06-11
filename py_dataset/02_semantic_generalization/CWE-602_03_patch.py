# In a real application, PRODUCT_CATALOG and SHIPPING_OPTIONS would be
# dynamically loaded from a database or configuration management system,
# not hardcoded directly in the module as static dictionaries.
# They represent the server's trusted source of truth for prices and rates.
PRODUCT_CATALOG = {
    "SKU-001": {"name": "Laptop", "price": 1200},
    "SKU-002": {"name": "Mouse", "price": 25},
    "SKU-003": {"name": "Keyboard", "price": 75},
}

SHIPPING_OPTIONS = {
    "standard": {"price": 10},
    "express": {"price": 25},
}

# Assume payment_gateway is an already defined and accessible object
# For demonstration purposes, if it were not defined, it might look like this:
# class PaymentGateway:
#     def authorize(self, amount: float) -> dict:
#         # In a real scenario, this would interact with a payment service
#         print(f"Authorizing payment for: ${amount}")
#         return {"status": "success", "amount": amount, "transaction_id": "mock_txn_123"}
# payment_gateway = PaymentGateway()

def submit_mobile_order(body: dict) -> dict:
    items_total = 0
    for item_data in body['items']:
        item_id = item_data.get('id')
        # Validate and retrieve quantity. The client can specify quantity,
        # but the server must ensure it's valid and available.
        quantity = int(item_data['count'])

        if not item_id or item_id not in PRODUCT_CATALOG:
            raise ValueError(f"Invalid or unknown item ID: {item_id}")
        
        if quantity <= 0:
            raise ValueError(f"Quantity for item {item_id} must be positive.")

        # Crucially, use the trusted price from the server's catalog,
        # not the client-provided price (which is vulnerable to manipulation).
        trusted_price = PRODUCT_CATALOG[item_id]['price']
        items_total += trusted_price * quantity
    
    # Similarly, use the trusted shipping fee based on the selected method,
    # not the client-provided shipping fee.
    shipping_method = body.get('shipping_method')
    if not shipping_method or shipping_method not in SHIPPING_OPTIONS:
        raise ValueError(f"Invalid or unknown shipping method: {shipping_method}")
    
    shipping_fee = SHIPPING_OPTIONS[shipping_method]['price']

    return payment_gateway.authorize(items_total + shipping_fee)
