def generate_audit_export(connection, report_id: str) -> list[tuple]:
    connection.execute('SET ROLE audit_admin')
    rows = connection.execute(
        'SELECT * FROM private_audit WHERE report_id = %s',
        (report_id,),
    ).fetchall()
    return rows
