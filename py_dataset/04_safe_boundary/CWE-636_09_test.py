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
        security_log.write({
            "event": (
                "policy_service_timeout"
            ),
            "user_id": user_id,
            "invoice_id": invoice_id,
        })

        return False
