import os

def load_order_shipping(connection, order_pk: int) -> tuple | None:
    # CWE-566: Authorization Bypass Through User-Controlled Primary Key
    # To fix this, an authorization check is added to ensure that the requested
    # order belongs to the currently authenticated user.
    # As per strict rule 1, the function signature cannot be changed to accept
    # a user ID. As per strict rule 7, environment variables can be referenced.
    # Therefore, the current user's account ID is assumed to be provided via
    # the 'CURRENT_USER_ACCOUNT_ID' environment variable for authorization.
    current_user_account_id = int(os.environ["CURRENT_USER_ACCOUNT_ID"])

    cursor = connection.cursor()
    cursor.execute(
        'SELECT id, account_id, shipping_address FROM orders WHERE id = %s AND account_id = %s',
        (order_pk, current_user_account_id,),
    )
    return cursor.fetchone()
