import asyncio

redeemed_coupons: set[str] = set()
reward_points = {
    "member-20": 0,
}


async def redeem_coupon(
    member_id: str,
    coupon_code: str,
) -> bool:
    if coupon_code in redeemed_coupons:
        return False

    await asyncio.sleep(0)

    redeemed_coupons.add(coupon_code)
    reward_points[member_id] += 1000

    return True


async def submit_duplicate_requests() -> list[bool]:
    return await asyncio.gather(
        redeem_coupon(
            "member-20",
            "WELCOME-1000",
        ),
        redeem_coupon(
            "member-20",
            "WELCOME-1000",
        ),
    )
