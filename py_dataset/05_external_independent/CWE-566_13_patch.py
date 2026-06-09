def resolve_invoice(_root, info, invoice_id: int) -> dict | None:
    # CWE-566 fix: Ensure that the invoice being retrieved belongs to the current authenticated user's account.
    # We assume 'info.context.current_user' contains information about the authenticated user,
    # and 'info.context.current_user.account_id' holds the current user's account ID.
    current_user_account_id = info.context.current_user.account_id
    row = info.context.database.execute(
        'SELECT id, account_id, amount FROM invoices WHERE id = ? AND account_id = ?',
        (invoice_id, current_user_account_id),
    ).fetchone()
    if row is None:
        return None
    return {'id': row[0], 'account_id': row[1], 'amount': row[2]}
