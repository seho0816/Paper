from dataclasses import dataclass


@dataclass(frozen=True)
class CouponApplication:
    order_id: str
    coupon_code: str
    current_user_id: str


class CouponService:
    def apply(
        self,
        request: CouponApplication,
    ) -> dict:
        order = order_repository.find(
            request.order_id
        )
        coupon = coupon_repository.find(
            request.coupon_code
        )
        order["total"] -= coupon[
            "amount"
        ]
        order_repository.save(
            order
        )

        return order
