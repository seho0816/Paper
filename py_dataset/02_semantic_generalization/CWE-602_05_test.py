def authorize_invoice(payload: dict) -> str:
    net_amount = int(payload['net_amount'])
    submitted_tax = int(payload['tax_amount'])
    return billing_client.charge(net_amount + submitted_tax)
