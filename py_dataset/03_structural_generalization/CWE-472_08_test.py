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
        total = subscription['renewal_price'] * (
            100 - discount
        ) // 100

        return self._invoices.create(
            subscription_id=subscription['id'],
            total=total,
        )
