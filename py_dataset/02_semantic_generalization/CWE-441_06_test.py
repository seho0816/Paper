def forward_billing_operation(
    billing_client,
    operation: str,
    payment_id: str,
):
    return billing_client.request(
        operation=operation,
        payment_id=payment_id,
        service_role="billing-admin",
    )
