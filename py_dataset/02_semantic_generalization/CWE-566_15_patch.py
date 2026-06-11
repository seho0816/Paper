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
    invoice_id = request_query["invoice_id"]

    # CWE-566: Authorization Bypass Through User-Controlled SQL Query.
    # To fix this, an authorization check is added.
    # It is assumed that 'user_id' in request_query represents the authenticated user's ID
    # and that this value is obtained from a trusted source (e.g., session, authenticated context),
    # not directly from untrusted user input that can be easily manipulated.
    current_user_id = request_query.get("user_id")

    invoice = repository.find_by_id(invoice_id)

    if invoice is None:
        return None

    # invoice[1] corresponds to the 'owner_id' column in the database result.
    # Perform the authorization check: ensure the invoice's owner_id matches the authenticated user's ID.
    if current_user_id is not None and invoice[1] == current_user_id:
        return invoice
    else:
        # If authorization fails (e.g., owner_id does not match or current_user_id is missing),
        # return None to prevent unauthorized access.
        return None
