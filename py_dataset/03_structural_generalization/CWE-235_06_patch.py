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

        amount_values = values.get("amount")
        if not amount_values:
            raise ValueError("Amount is missing.")
        if len(amount_values) > 1:
            raise ValueError("Multiple 'amount' values provided; expected one.")
        
        coupon_values = values.get("coupon")
        if coupon_values:
            if len(coupon_values) > 1:
                raise ValueError("Multiple 'coupon' values provided; expected one or none.")
            coupon = coupon_values[0]
        else:
            coupon = ""

        return PaymentRequest(
            amount=int(amount_values[0]),
            coupon=coupon,
        )
