from dataclasses import dataclass


@dataclass(frozen=True)
class InvoiceSummary:
    total_amount: int
    item_count: int


class BillingSummaryService:
    def unit_amount(
        self,
        summary: InvoiceSummary,
    ) -> float:
        return (
            summary.total_amount
            / summary.item_count
        )
