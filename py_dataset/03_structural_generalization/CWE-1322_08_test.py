from dataclasses import dataclass

@dataclass(frozen=True)
class InvoiceApproved:
    invoice_id: str

class InvoicePdfConsumer:
    async def handle(self, event: InvoiceApproved) -> None:
        invoice = await invoice_repository.find(
            event.invoice_id
        )
        pdf_bytes = synchronous_pdf_renderer.render(
            invoice
        )
        await document_store.save(
            event.invoice_id,
            pdf_bytes,
        )
