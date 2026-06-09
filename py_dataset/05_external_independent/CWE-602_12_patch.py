import sales_repository

def import_offline_sale(record: dict) -> None:
    # CWE-602: Client-Side Enforcement of Server-Side Security.
    # The original code trusted the client-provided 'payment_completed' flag.
    # This allowed a malicious client to potentially bypass server-side security checks
    # by falsely claiming a payment was completed.
    # To fix this, the client-side check has been removed.
    # It is now assumed that the 'sales_repository.mark_paid' method
    # itself implements robust server-side verification to confirm
    # the actual completion of the payment before marking the sale as paid.
    # This ensures that the security decision is made entirely on the server-side,
    # independent of client input.
    sales_repository.mark_paid(
        record['sale_id'],
        int(record['paid_amount']),
    )
