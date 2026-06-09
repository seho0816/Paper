def export_partner_record(customer_model) -> None:
    partner_client.send(
        customer_model.model_dump()
    )
