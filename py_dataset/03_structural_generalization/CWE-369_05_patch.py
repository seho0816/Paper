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
        if summary.item_count == 0:
            # Prevent CWE-369: Division by Zero.
            # If there are no items, the unit amount is 0.0, or this could indicate an invalid state.
            # Returning 0.0 is a common safe default for a unit amount when the count is zero.
            return 0.0
        return (
            summary.total_amount
            / summary.item_count
        )
