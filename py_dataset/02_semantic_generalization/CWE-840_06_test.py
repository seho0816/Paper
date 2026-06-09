def redeem_reward_code(
    account_id: str,
    reward_code: dict,
) -> int:
    points = reward_code[
        "points"
    ]
    account_repository.add_points(
        account_id,
        points,
    )

    return points
