class ShippingQuoteMapper:
    def from_form(
        self,
        form: dict,
    ) -> dict:
        # Validate 'destination'
        destination = form.get('destination')
        if not isinstance(destination, str) or not destination.strip():
            raise ValueError("Invalid or missing 'destination'.")
        destination = destination.strip()

        # Validate 'weight_kg'
        try:
            weight_kg_val = form.get('weight_kg')
            if weight_kg_val is None:
                raise ValueError("Missing 'weight_kg'.")
            weight_kg = float(weight_kg_val)
            if weight_kg < 0:
                raise ValueError("'weight_kg' cannot be negative.")
        except (ValueError, TypeError):
            raise ValueError("Invalid format for 'weight_kg'. Must be a non-negative number.")

        # Validate 'shipping_fee'
        try:
            shipping_fee_val = form.get('shipping_fee')
            if shipping_fee_val is None:
                raise ValueError("Missing 'shipping_fee'.")
            
            # Allow conversion from float if it's an integer value (e.g., 10.0)
            # but disallow non-integer floats (e.g., 10.5)
            if isinstance(shipping_fee_val, float) and not shipping_fee_val.is_integer():
                raise ValueError("Invalid format for 'shipping_fee'. Must be an integer.")
            
            shipping_fee = int(shipping_fee_val)
            if shipping_fee < 0:
                raise ValueError("'shipping_fee' cannot be negative.")
        except (ValueError, TypeError):
            raise ValueError("Invalid format for 'shipping_fee'. Must be a non-negative integer.")

        return {
            'destination': destination,
            'weight_kg': weight_kg,
            'shipping_fee': shipping_fee,
        }


async def create_shipping_order(
    form: dict,
) -> dict:
    quote = ShippingQuoteMapper().from_form(
        form
    )
    # shipment_store is an assumed external dependency, not part of the CWE-472 fix
    # and its behavior is not modified.
    shipment_id = await shipment_store.create(
        destination=quote['destination'],
        weight_kg=quote['weight_kg'],
        payable_amount=quote['shipping_fee'],
    )

    return {
        'shipment_id': shipment_id,
        'payable_amount': quote['shipping_fee'],
    }
