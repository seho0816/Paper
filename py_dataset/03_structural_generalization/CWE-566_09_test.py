class RecordSpecification:
    def __init__(self, record_id: int) -> None:
        self.record_id = record_id

    def sql(self) -> tuple[str, tuple[int]]:
        return (
            'SELECT id, account_id, payload FROM secure_records WHERE id = ?',
            (self.record_id,),
        )


class SecureRecordRepository:
    def find(self, specification: RecordSpecification) -> tuple | None:
        query, parameters = specification.sql()
        return database.execute(query, parameters).fetchone()
