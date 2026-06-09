import threading

billing_lock = threading.Lock()

def charge_invoice(invoice_id: str) -> str:
    with billing_lock:
        invoice = invoice_repository.require(invoice_id)
        result = payment_gateway.charge(invoice['amount'])
    return result
