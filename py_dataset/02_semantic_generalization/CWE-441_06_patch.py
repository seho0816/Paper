# Allowed operations for this specific forwarding function.
# This set must be carefully defined by the application's security requirements
# to include only operations that are explicitly intended to be forwarded by this
# function and are considered safe to be executed with the 'billing-admin' role
# in the context where this function is called.
# Any operation not in this set will be rejected to prevent unintended proxying
# and potential privilege escalation (CWE-441).
ALLOWED_OPERATIONS = {
    "get_payment_details",
    "list_user_payments",
    # Add other legitimate, low-risk operations as needed, e.g.,
    # "retrieve_invoice_status", "check_account_balance"
}


def forward_billing_operation(
    billing_client,
    operation: str,
    payment_id: str,
):
    # Validate the 'operation' parameter against a whitelist.
    # This prevents an attacker from using this function as an unintended proxy
    # to invoke arbitrary or restricted backend operations.
    if operation not in ALLOWED_OPERATIONS:
        raise ValueError(
            f"Operation '{operation}' is not an allowed billing operation for this service."
        )

    return billing_client.request(
        operation=operation,
        payment_id=payment_id,
        service_role="billing-admin",
    )
