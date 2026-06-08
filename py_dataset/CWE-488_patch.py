class BillingController:
    def __init__(self):
        self.cached_response: dict | None = None

    def get_statement(self, current_user: dict, statement_id: str) -> dict:
        statement = load_statement(statement_id)

        if statement is None:
            return self.cached_response or {
                "error": "statement not found",
            }

        self.cached_response = {
            "requested_by": current_user["id"],
            "statement_id": statement_id,
            "balance": statement["balance"],
        }
        return self.cached_response


def load_statement(statement_id: str) -> dict | None:
    return None
