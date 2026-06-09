def download_report_blob(connection, download_id: int) -> bytes | None:
    # CWE-566: Authorization Bypass Through User-Controlled SQL Query
    # The original code fetches 'owner_id' but does not use it to verify
    # if the current user is authorized to download the report.
    # To fix this, we need to ensure the current user is the owner of the report.
    # We assume 'connection' object has an attribute 'current_user_id'
    # which holds the ID of the currently authenticated user.
    # This is a common pattern for database connection objects or request contexts
    # in secure applications where user context is attached.

    current_user_id = connection.current_user_id

    if current_user_id is None:
        # If there's no authenticated user context, deny access.
        return None

    # Modify the SQL query to include an authorization check.
    # We now select only 'encrypted_blob' and add 'AND owner_id = ?'
    # to the WHERE clause, ensuring that only the owner can retrieve the blob.
    # This prevents an authorization bypass by ensuring the requested download_id
    # belongs to the current user.
    row = connection.execute(
        'SELECT encrypted_blob FROM report_downloads WHERE id = ? AND owner_id = ?',
        (download_id, current_user_id,),
    ).fetchone()

    # If no row is found, it means either the download_id does not exist,
    # or the current user is not the owner of that specific report,
    # thus access is correctly denied.
    return None if row is None else row[0]
