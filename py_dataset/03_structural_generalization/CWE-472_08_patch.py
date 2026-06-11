from typing import TypedDict


class RenewalRequest(TypedDict):
    subscription_id: str
    submitted_discount_percent: int


class RenewalPipeline:
    def __init__(
        self,
        subscriptions,
        invoices,
    ) -> None:
        self._subscriptions = subscriptions
        self._invoices = invoices

    def execute(
        self,
        request: RenewalRequest,
    ) -> dict:
        subscription = self._subscriptions.load(
            request['subscription_id']
        )
        discount = request[
            'submitted_discount_percent'
        ]

        # CWE-472 Fix: Validate the externally controlled discount percentage.
        # An assumed immutable property of a discount is that it should be within a valid range (e.g., 0-100%).
        # External control without validation can lead to unexpected or harmful calculations.
        if not (0 <= discount <= 100):
            raise ValueError("Submitted discount percentage must be between 0 and 100, inclusive.")

        total = subscription['renewal_price'] * (
            100 - discount
        ) // 100

        return self._invoices.create(
            subscription_id=subscription['id'],
            total=total,
        )
