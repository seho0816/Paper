from dataclasses import dataclass


@dataclass(frozen=True)
class SignedCoupon:
    coupon_id: str
    account_id: str
    signature: str


class CouponService:
    def redeem(
        self,
        coupon: SignedCoupon,
    ) -> bool:
        if not verify_coupon_signature(
            coupon
        ):
            return False

        add_reward_points(
            coupon.account_id,
            1000,
        )
        return True
