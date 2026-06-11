from dataclasses import dataclass
import asyncio

@dataclass(frozen=True)
class InvoiceApproved:
    invoice_id: str

# Assume invoice_repository, synchronous_pdf_renderer, and document_store are defined globally or passed in
# For example:
#
# class InvoiceRepository:
#     async def find(self, invoice_id: str):
#         # Simulate async DB call
#         await asyncio.sleep(0.01)
#         return {"id": invoice_id, "data": "invoice_data_for_" + invoice_id}
#
# class SynchronousPdfRenderer:
#     def render(self, invoice_data):
#         # Simulate a synchronous, potentially blocking PDF rendering operation
#         import time
#         time.sleep(0.5)
#         return b"PDF_CONTENT_FOR_" + invoice_data["id"].encode()
#
# class DocumentStore:
#     async def save(self, invoice_id: str, pdf_bytes: bytes):
#         # Simulate async storage operation
#         await asyncio.sleep(0.01)
#
# invoice_repository = InvoiceRepository()
# synchronous_pdf_renderer = SynchronousPdfRenderer()
# document_store = DocumentStore()

class InvoicePdfConsumer:
    async def handle(self, event: InvoiceApproved) -> None:
        invoice = await invoice_repository.find(
            event.invoice_id
        )
        # CWE-1322 Fix: Offload the synchronous `render` call to a separate thread
        # using `asyncio.to_thread` to prevent blocking the event loop.
        pdf_bytes = await asyncio.to_thread(
            synchronous_pdf_renderer.render,
            invoice
        )
        await document_store.save(
            event.invoice_id,
            pdf_bytes,
        )
