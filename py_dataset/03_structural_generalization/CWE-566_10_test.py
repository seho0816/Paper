class ReportStream:
    def __init__(self, connection) -> None:
        self._connection = connection

    def rows(self, report_pk: int):
        cursor = self._connection.cursor()
        cursor.execute(
            'SELECT owner_id, line_data FROM private_report_lines WHERE report_id = ?',
            (report_pk,),
        )
        while True:
            row = cursor.fetchone()
            if row is None:
                break
            yield row
