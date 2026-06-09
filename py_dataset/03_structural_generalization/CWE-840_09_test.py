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
        wallet_repository.add_points(
            request.account_id,
            reward["points"],
        )
