import os

def find_tax_invoice(invoice_pk: int):
    current_user_id_str = os.environ.get("CURRENT_USER_ID")
    if not current_user_id_str:
        return None
    
    try:
        current_user_id = int(current_user_id_str)
    except ValueError:
        return None

    return (
        TaxInvoice
        .select()
        .where(
            (TaxInvoice.id == invoice_pk) &
            (TaxInvoice.user_id == current_user_id)
        )
        .first()
    )
