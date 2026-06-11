def finalize_expense(expense: dict) -> dict:
    # CWE-841 fix: Ensure the expense is in a valid state for payment.
    # An expense should only transition to 'paid' from specific preceding states,
    # such as 'pending' or 'approved'.
    valid_pre_payment_statuses = ['pending', 'approved']
    current_status = expense.get('status')

    if current_status not in valid_pre_payment_statuses:
        # Prevent an improper state transition if the expense is not in a
        # state that allows it to be finalized as paid (e.g., already paid, rejected).
        raise ValueError(
            f"Invalid state transition: Expense with status '{current_status}' "
            f"cannot be finalized. Must be one of: {valid_pre_payment_statuses}"
        )

    expense['status'] = 'paid'
    expense['paid_at'] = current_time() # current_time() is assumed to be defined elsewhere in the application.
    return expense
