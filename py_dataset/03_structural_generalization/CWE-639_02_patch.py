from dataclasses import dataclass

from flask import Flask, jsonify, request, abort

app = Flask(__name__)


@dataclass(frozen=True)
class InvoiceRequest:
    invoice_id: str
    actor_id: str


class InvoiceRepository:
    def __init__(self) -> None:
        self._invoices = {
            "inv-100": {
                "owner_id": "user-1",
                "amount": 50000,
            },
            "inv-200": {
                "owner_id": "user-2",
                "amount": 90000,
            },
        }

    def find_by_id(self, invoice_id: str) -> dict:
        return self._invoices[invoice_id]


class InvoiceQueryService:
    def __init__(
        self,
        repository: InvoiceRepository,
    ) -> None:
        self._repository = repository

    def execute(
        self,
        query: InvoiceRequest,
    ) -> dict:
        invoice = self._repository.find_by_id(
            query.invoice_id,
        )

        # CWE-639 fix: Authorization check to prevent unauthorized access.
        # Ensure that the actor_id matches the invoice's owner_id.
        if invoice["owner_id"] != query.actor_id:
            abort(403, description="Access to invoice forbidden")

        return {
            "requested_by": query.actor_id,
            "invoice": invoice,
        }


service = InvoiceQueryService(InvoiceRepository())


@app.get("/api/invoices/<invoice_id>")
def get_invoice(invoice_id: str):
    query = InvoiceRequest(
        invoice_id=invoice_id,
        actor_id=request.headers.get(
            "X-User-Id",
            "",
        ),
    )

    return jsonify(service.execute(query))
