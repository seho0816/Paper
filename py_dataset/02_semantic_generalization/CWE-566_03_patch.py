import os

async def fetch_payment(connection, payment_id: int) -> dict | None:
    service_account_id = int(os.environ["SERVICE_ACCOUNT_ID"])
    row = await connection.fetchrow(
        'SELECT id, account_id, card_last4, amount FROM payments WHERE id = $1 AND account_id = $2',
        payment_id,
        service_account_id,
    )
    return dict(row) if row is not None else None
