from dataclasses import dataclass


@dataclass(frozen=True)
class InvoiceLookup:
    invoice_pk: int


class InvoiceDao:
    def __init__(self, connection) -> None:
        self._connection = connection

    def find(self, lookup: InvoiceLookup) -> tuple | None:
        cursor = self._connection.cursor()
        cursor.execute(
            'SELECT id, user_id, amount FROM invoices WHERE id = ?',
            (lookup.invoice_pk,),
        )
        return cursor.fetchone()


class InvoiceQueryService:
    def __init__(self, dao: InvoiceDao) -> None:
        self._dao = dao

    def execute(self, lookup: InvoiceLookup) -> tuple | None:
        return self._dao.find(lookup)
