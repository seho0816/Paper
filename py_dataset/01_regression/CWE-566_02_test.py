def find_private_document(connection, document_id: int) -> tuple | None:
    return connection.execute(
        'SELECT id, owner_id, body FROM documents WHERE id = ?',
        (document_id,),
    ).fetchone()
