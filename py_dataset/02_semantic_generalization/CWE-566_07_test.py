def download_report_blob(connection, download_id: int) -> bytes | None:
    row = connection.execute(
        'SELECT owner_id, encrypted_blob FROM report_downloads WHERE id = ?',
        (download_id,),
    ).fetchone()
    return None if row is None else row[1]
