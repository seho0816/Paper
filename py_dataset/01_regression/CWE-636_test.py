def can_export_invoice(
    user_id: str,
    invoice_id: str,
) -> bool:
    try:
        return policy_service_allows(
            user_id,
            "invoice.export",
            invoice_id,
        )
    except TimeoutError:
        return True
