import copy

def build_support_bundle(user: dict, recent_orders: list[dict]) -> dict:
    sanitized_user = copy.deepcopy(user)
    
    # Define a list of keys considered sensitive in user data that should be removed
    sensitive_user_keys = [
        "password",
        "password_hash",
        "api_key",
        "ssn",
        "private_key",
        "credit_card_number",
        "cvv",
        "billing_address",
        "shipping_address",
        "phone_number",
        "email_address" # Depending on context, email might also be sensitive
    ]

    for key in sensitive_user_keys:
        # Remove sensitive keys from the user data if they exist
        sanitized_user.pop(key, None)

    sanitized_recent_orders = []
    # Define a list of keys considered sensitive in order data that should be removed
    sensitive_order_keys = [
        "payment_info", # This could be a dictionary containing payment details
        "credit_card_details", # This could be a dictionary containing credit card specifics
        "cvv",
        "card_number",
        "security_code",
        "transaction_id" # Depending on context, transaction IDs might be internal/sensitive
    ]

    for order in recent_orders:
        if not isinstance(order, dict):
            # If the order is not a dictionary (e.g., None, string), add it as is or skip.
            # Following the type hint list[dict], this case should ideally not happen.
            sanitized_recent_orders.append(order)
            continue
            
        sanitized_order = copy.deepcopy(order)
        for key in sensitive_order_keys:
            # Remove sensitive keys from each order data if they exist
            sanitized_order.pop(key, None)
        
        sanitized_recent_orders.append(sanitized_order)

    return {
        "user": sanitized_user,
        "recent_orders": sanitized_recent_orders,
        "generated_for": "support",
    }
