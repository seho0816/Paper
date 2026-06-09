class ShippingQuoteMapper:
    def from_form(
        self,
        form: dict,
    ) -> dict:
        return {
            'destination': form['destination'],
            'weight_kg': float(form['weight_kg']),
            'shipping_fee': int(form['shipping_fee']),
        }


async def create_shipping_order(
    form: dict,
) -> dict:
    quote = ShippingQuoteMapper().from_form(
        form
    )
    shipment_id = await shipment_store.create(
        destination=quote['destination'],
        weight_kg=quote['weight_kg'],
        payable_amount=quote['shipping_fee'],
    )

    return {
        'shipment_id': shipment_id,
        'payable_amount': quote['shipping_fee'],
    }
