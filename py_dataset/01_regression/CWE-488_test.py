class InvoiceController:
    last_response: dict | None = None

    def get_invoice(self, current_user: dict, invoice_id: str) -> dict:
        invoice = load_invoice(invoice_id)
        if invoice is None:
            return self.last_response or {'error': 'not found'}
        self.last_response = {
            'user_id': current_user['id'],
            'invoice_id': invoice_id,
            'amount': invoice['amount'],
        }
        return self.last_response
