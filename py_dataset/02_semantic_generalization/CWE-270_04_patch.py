def generate_audit_export(connection, report_id: str) -> list[tuple]:
    try:
        connection.execute('SET ROLE audit_admin')
        rows = connection.execute(
            'SELECT * FROM private_audit WHERE report_id = %s',
            (report_id,),
        ).fetchall()
        return rows
    finally:
        # CWE-270: Ensure privileges are dropped after the sensitive operation.
        # This prevents subsequent operations on the same connection from
        # unintentionally running with elevated 'audit_admin' privileges.
        connection.execute('RESET ROLE')
