def internal_invoice_export(
    invoice_id: str,
) -> bytes:
    invoice = invoice_repository.find(
        invoice_id
    )

    return render_invoice_pdf(
        invoice
    )
