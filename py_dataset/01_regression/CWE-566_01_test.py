def load_order_shipping(connection, order_pk: int) -> tuple | None:
    cursor = connection.cursor()
    cursor.execute(
        'SELECT id, account_id, shipping_address FROM orders WHERE id = %s',
        (order_pk,),
    )
    return cursor.fetchone()
