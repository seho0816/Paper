from dataclasses import dataclass


@dataclass(frozen=True)
class PaymentRequest:
    invoice_id: str


class PaymentService:
    def charge(
        self,
        request: PaymentRequest,
    ) -> str:
        invoice = invoice_repository.find(
            request.invoice_id
        )
        if invoice is None:
            raise ValueError(f"Invoice with ID {request.invoice_id} not found.")
        amount = invoice.calculate_payable_amount()

        return payment_gateway.charge(
            amount
        )
