def redeem_reward_code(
    account_id: str,
    reward_code: dict,
) -> int:
    points = reward_code[
        "points"
    ]
    # CWE-840: Business Logic Error - Reward points should be a positive integer.
    # Validate that 'points' is an integer and is strictly positive to prevent
    # negative point redemption or non-integer errors that could bypass business rules
    # or cause unexpected behavior in `account_repository.add_points`.
    if not isinstance(points, int) or points <= 0:
        points = 0  # Treat invalid or non-positive points as 0 points to be added.

    account_repository.add_points(
        account_id,
        points,
    )

    return points
