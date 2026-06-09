def load_order_for_account(connection, account_id: str, order_pk: int) -> tuple:
    row = connection.execute(
        'SELECT id, account_id, total FROM orders WHERE id = ?',
        (order_pk,),
    ).fetchone()
    if row is None:
        raise LookupError('order not found')
    if row[1] != account_id:
        raise PermissionError('order owner mismatch')
    return row
