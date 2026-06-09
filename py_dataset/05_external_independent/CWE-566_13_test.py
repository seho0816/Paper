def resolve_invoice(_root, info, invoice_id: int) -> dict | None:
    row = info.context.database.execute(
        'SELECT id, account_id, amount FROM invoices WHERE id = ?',
        (invoice_id,),
    ).fetchone()
    if row is None:
        return None
    return {'id': row[0], 'account_id': row[1], 'amount': row[2]}
