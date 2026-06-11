from dataclasses import dataclass


@dataclass(frozen=True)
class SocketSession:
    user_id: str


invoices = {
    "invoice-11": {
        "owner_id": "user-11",
        "amount": 55000,
    },
    "invoice-22": {
        "owner_id": "user-22",
        "amount": 86000,
    },
}


async def handle_invoice_message(
    session: SocketSession,
    message: dict,
) -> dict:
    invoice_id = str(message["invoice_id"])
    invoice = invoices[invoice_id]

    # CWE-639: Authorization Bypass Through User-Controlled Key
    # Fix: Verify that the requesting user is authorized to access this invoice.
    if invoice["owner_id"] != session.user_id:
        raise ValueError("Unauthorized access to invoice.")

    return {
        "requested_by": session.user_id,
        "invoice": invoice,
    }
