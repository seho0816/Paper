from dataclasses import dataclass


@dataclass(frozen=True)
class RewardRedemption:
    account_id: str
    reward_code: str


class RewardService:
    def redeem(
        self,
        request: RewardRedemption,
    ) -> None:
        reward = reward_repository.find(
            request.reward_code
        )

        if not reward:
            raise ValueError("Reward not found.")

        if reward.get("is_redeemed"):
            raise ValueError("Reward already redeemed.")

        wallet_repository.add_points(
            request.account_id,
            reward["points"],
        )

        try:
            reward_repository.mark_as_redeemed(
                request.reward_code,
                request.account_id,
            )
        except Exception as e:
            raise RuntimeError("Failed to mark reward as redeemed after adding points.") from e
