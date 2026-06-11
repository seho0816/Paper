import asyncio

redeemed_coupons: set[str] = set()
reward_points = {
    "member-20": 0,
}

# CWE-362 fix: Use an asyncio.Lock to protect the shared resources
# (redeemed_coupons and reward_points) during concurrent access.
_coupon_redemption_lock = asyncio.Lock()


async def redeem_coupon(
    member_id: str,
    coupon_code: str,
) -> bool:
    # Acquire the lock to ensure only one task can execute the critical section
    # (check if coupon is redeemed, then add it and update points) at a time.
    async with _coupon_redemption_lock:
        if coupon_code in redeemed_coupons:
            return False

        # The await asyncio.sleep(0) is part of the original code's structure.
        # With the lock in place, it no longer introduces a race condition.
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
