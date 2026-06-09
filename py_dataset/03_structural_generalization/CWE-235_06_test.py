from dataclasses import dataclass
from urllib.parse import parse_qs


@dataclass(frozen=True)
class PaymentRequest:
    amount: int
    coupon: str


class PaymentRequestMapper:
    def map(
        self,
        query_string: str,
    ) -> PaymentRequest:
        values = parse_qs(
            query_string
        )

        return PaymentRequest(
            amount=int(
                values["amount"][0]
            ),
            coupon=values.get(
                "coupon",
                [""],
            )[0],
        )
