def find_tax_invoice(invoice_pk: int):
    return (
        TaxInvoice
        .select()
        .where(TaxInvoice.id == invoice_pk)
        .first()
    )
