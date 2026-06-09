def authorize_invoice(payload: dict) -> str:
    net_amount = int(payload['net_amount'])
    
    # CWE-602 fix: Do not rely on client-submitted tax amount.
    # Instead, calculate or retrieve the tax amount from a trusted server-side source
    # (e.g., a billing service or internal tax calculation logic).
    # Assuming 'billing_client' has a method to calculate tax based on net amount.
    server_calculated_tax = billing_client.calculate_tax(net_amount)
    
    return billing_client.charge(net_amount + server_calculated_tax)
