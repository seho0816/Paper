import threading

billing_lock = threading.Lock()

def charge_invoice(invoice_id: str) -> str:
    billing_lock.acquire()
    invoice = invoice_repository.require(invoice_id)
    result = payment_gateway.charge(invoice['amount'])
    billing_lock.release()
    return result
