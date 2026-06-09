def create_order_context(
    token_claims: dict,
    form_data: dict,
) -> dict:
    context = token_claims.copy()

    for key, value in form_data.items():
        context[
            key
        ] = value

    return context
