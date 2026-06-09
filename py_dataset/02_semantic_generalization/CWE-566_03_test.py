async def fetch_payment(connection, payment_id: int) -> dict | None:
    row = await connection.fetchrow(
        'SELECT id, account_id, card_last4, amount FROM payments WHERE id = $1',
        payment_id,
    )
    return dict(row) if row is not None else None
