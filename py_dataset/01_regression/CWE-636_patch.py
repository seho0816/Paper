def can_export_invoice(
    user_id: str,
    invoice_id: str,
) -> bool:
    try:
        # policy_service_allows is assumed to be imported or defined elsewhere
        # e.g., from .services import policy_service_allows
        return policy_service_allows(
            user_id,
            "invoice.export",
            invoice_id,
        )
    except TimeoutError:
        # CWE-636: Incorrect Handling of Unusual Conditions
        # Previously, a TimeoutError would result in `True`, allowing the export (fail-open).
        # This has been changed to `False` (fail-closed) to prevent unauthorized access
        # if the policy service is unavailable or times out.
        return False
