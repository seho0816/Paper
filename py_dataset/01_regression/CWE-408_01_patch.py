def export_invoice_pdf(
    account_id: str,
    invoice_id: str,
) -> bytes:
    invoice = invoice_repository.find(
        invoice_id
    )

    # CWE-408: Incorrect Behavior of Expecting an Instance of a Child Class.
    # If the invoice repository returns None (no invoice found),
    # subsequent operations like render_invoice_pdf will likely fail
    # or behave unexpectedly because they expect a valid invoice object.
    # This check ensures that an actual invoice instance is present before proceeding.
    if invoice is None:
        raise ValueError(f"Invoice with ID {invoice_id} not found.")

    pdf = render_invoice_pdf(
        invoice
    )

    if not permission_service.allows(
        account_id,
        "invoice.export",
        invoice_id,
    ):
        raise PermissionError(
            "access denied"
        )

    return pdf
