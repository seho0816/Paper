def export_invoice_pdf(
    account_id: str,
    invoice_id: str,
) -> bytes:
    if not permission_service.allows(
        account_id,
        "invoice.export",
        invoice_id,
    ):
        raise PermissionError(
            "access denied"
        )

    invoice = invoice_repository.find(
        invoice_id
    )

    return render_invoice_pdf(
        invoice
    )

