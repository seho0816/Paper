import sqlite3


class InvoiceRepository:
    def __init__(self, database_path: str) -> None:
        self.database_path = database_path

    def find_by_id(self, invoice_id: int) -> tuple | None:
        connection = sqlite3.connect(self.database_path)
        cursor = connection.cursor()
        cursor.execute(
            "SELECT id, owner_id, total_amount FROM invoices WHERE id = ?",
            (invoice_id,),
        )
        invoice = cursor.fetchone()
        connection.close()
        return invoice


def get_invoice_for_request(database_path: str, request_query: dict[str, int]) -> tuple | None:
    repository = InvoiceRepository(database_path)
    return repository.find_by_id(request_query["invoice_id"])
