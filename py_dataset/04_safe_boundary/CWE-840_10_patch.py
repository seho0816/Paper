from datetime import datetime, timezone


def apply_coupon(
    order: dict,
    coupon: dict,
    current_user_id: str,
) -> dict:
    now = datetime.now(
        timezone.utc
    )

    if coupon.get(
        "used"
    ):
        raise ValueError(
            "coupon already used"
        )

    if coupon.get(
        "owner_user_id"
    ) != current_user_id:
        raise PermissionError(
            "coupon owner mismatch"
        )

    if datetime.fromisoformat(
        coupon["expires_at"]
    ) <= now:
        raise ValueError(
            "coupon expired"
        )

    if coupon["code"] in order.get(
        "applied_coupons",
        [],
    ):
        raise ValueError(
            "coupon already applied"
        )

    return coupon_repository.apply_atomically(
        order,
        coupon,
        current_user_id,
    )

