def export_invoice_pdf(
    account_id: str,
    invoice_id: str,
) -> bytes:
    invoice = invoice_repository.find(
        invoice_id
    )
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
