from dataclasses import dataclass


# CWE-294: Authentication Bypass. The vulnerability arises if the critical
# authentication function (verify_coupon_signature) is missing, improperly
# defined, or easily bypassed. To patch this within the scope of this file,
# we must ensure the `verify_coupon_signature` function is defined and
# defaults to a secure (fail-safe) state if a full, cryptographic implementation
# is not provided externally. This prevents an attacker from bypassing
# authentication due to an undefined or insecure stub.

# Secure stub for `verify_coupon_signature`.
# In a real application, this function would contain robust cryptographic
# verification logic using secure keys and algorithms.
# As a secure patch for CWE-294, if no proper implementation is available,
# this function must return False by default to prevent any authentication bypass.
def verify_coupon_signature(coupon: 'SignedCoupon') -> bool:
    return False

# Placeholder for `add_reward_points`.
# This function typically interacts with a backend system to apply rewards.
# Its implementation is not directly related to CWE-294, but it is necessary
# for the provided code to be grammatically complete and executable as per rules.
def add_reward_points(account_id: str, points: int) -> None:
    pass


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
        # The explicit check `if not verify_coupon_signature(coupon)` is
        # crucial for preventing authentication bypass (CWE-294).
        # With the added fail-secure stub for `verify_coupon_signature`,
        # this code path is now protected even if the external implementation
        # of signature verification is missing or weak.
        if not verify_coupon_signature(
            coupon
        ):
            return False

        add_reward_points(
            coupon.account_id,
            1000,
        )
        return True
