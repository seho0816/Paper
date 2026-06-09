class InvoiceController:
    def get_invoice(self, current_user: dict, invoice_id: str) -> dict:
        invoice = load_invoice(invoice_id)
        if invoice is None:
            return {'error': 'not found'}
        if invoice['user_id'] != current_user['id']:
            raise PermissionError('invoice owner mismatch')
        return {
            'user_id': current_user['id'],
            'invoice_id': invoice_id,
            'amount': invoice['amount'],
        }

