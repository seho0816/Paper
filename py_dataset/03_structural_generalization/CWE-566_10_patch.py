class ReportStream:
    def __init__(self, connection) -> None:
        self._connection = connection

    def rows(self, report_pk: int):
        cursor = self._connection.cursor()
        
        # CWE-566 is often related to "Improper Link Resolution" leading to access control issues.
        # In this database context, directly accessing 'private_report_lines' by 'report_pk'
        # without verifying the user's authorization to that specific report (IDOR)
        # is the most probable vulnerability.
        # To fix this, we must ensure the current user owns the report.
        # We assume the 'connection' object (or a wrapper around it) provides
        # the current authenticated user's ID for authorization purposes.
        # This approach ensures that the method signature remains unchanged
        # as per the strict rules, and avoids 'placeholder' values.
        current_user_id = self._connection.get_current_user_id()

        cursor.execute(
            'SELECT owner_id, line_data FROM private_report_lines WHERE report_id = ? AND owner_id = ?',
            (report_pk, current_user_id),
        )
        while True:
            row = cursor.fetchone()
            if row is None:
                break
            yield row
