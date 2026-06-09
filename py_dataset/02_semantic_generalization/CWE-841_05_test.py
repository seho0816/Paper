def finalize_expense(expense: dict) -> dict:
    expense['status'] = 'paid'
    expense['paid_at'] = current_time()
    return expense
