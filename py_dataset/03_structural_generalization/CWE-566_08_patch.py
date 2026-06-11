import os
from dataclasses import dataclass


@dataclass(frozen=True)
class InvoiceLookup:
    invoice_pk: int


class InvoiceDao:
    def __init__(self, connection) -> None:
        self._connection = connection

    def find(self, lookup: InvoiceLookup) -> tuple | None:
        cursor = self._connection.cursor()
        
        # CWE-566: Authorization Bypass Through SQL Predicate Manipulation
        # The original query 'WHERE id = ?' allowed fetching any invoice by ID,
        # potentially bypassing authorization checks if a user could query invoices
        # they do not own. To fix this, the query must include an authorization
        # predicate that restricts results to the current user's invoices.
        # As per rule 7, current user ID is obtained from an environment variable.
        
        try:
            current_user_id_str = os.environ["CURRENT_USER_ID"]
            current_user_id = int(current_user_id_str)
        except (KeyError, ValueError):
            # If "CURRENT_USER_ID" environment variable is not set or its value
            # is not a valid integer, it indicates an improper authorization context.
            # In such a scenario, the query cannot be securely executed.
            # An exception is raised to prevent unauthorized access or system misbehavior.
            # This ensures a secure fail-fast approach without introducing new vulnerabilities
            # or altering method signatures.
            raise ValueError("CURRENT_USER_ID environment variable is missing or invalid for authorization.")

        # The SQL query is modified to include an authorization predicate.
        # It now ensures that only invoices belonging to the 'current_user_id' can be fetched.
        cursor.execute(
            'SELECT id, user_id, amount FROM invoices WHERE id = ? AND user_id = ?',
            (lookup.invoice_pk, current_user_id),
        )
        return cursor.fetchone()


class InvoiceQueryService:
    def __init__(self, dao: InvoiceDao) -> None:
        self._dao = dao

    def execute(self, lookup: InvoiceLookup) -> tuple | None:
        return self._dao.find(lookup)
