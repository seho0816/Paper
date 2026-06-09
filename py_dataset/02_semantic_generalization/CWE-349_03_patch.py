def create_order_context(
    token_claims: dict,
    form_data: dict,
) -> dict:
    context = token_claims.copy()

    # Define a whitelist of keys that are legitimately expected from form_data.
    # Any keys not in this list will be ignored, preventing extraneous untrusted data.
    # The specific keys should be determined by the application's design for an order context.
    ALLOWED_FORM_DATA_KEYS = [
        "item_id",
        "quantity",
        "shipping_address",
        "billing_address",
        "payment_method",
        "delivery_instructions",
        "coupon_code",
    ]

    for key, value in form_data.items():
        if key in ALLOWED_FORM_DATA_KEYS:
            context[key] = value

    return context
