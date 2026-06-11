def find_private_document(connection, document_id: int) -> tuple | None:
    # CWE-566: Improper Link Resolution Before File Access ('"Time-of-Check Time-of-Use' Race Condition)
    # In a database context, this often translates to a TOCTOU condition related to authorization.
    # If access control is checked externally and then this function is called, a race condition
    # could allow access if permissions change between the check and the data retrieval.
    # To mitigate this, the access control check (ownership) is integrated directly into the query,
    # making it an atomic operation within the database transaction.
    # This assumes that the 'connection' object provides the current user's ID
    # (e.g., in a framework context where the connection or session is user-scoped).
    current_user_id = connection.current_user_id # Assumes current_user_id is available via the connection object
    return connection.execute(
        'SELECT id, owner_id, body FROM documents WHERE id = ? AND owner_id = ?',
        (document_id, current_user_id,),
    ).fetchone()
