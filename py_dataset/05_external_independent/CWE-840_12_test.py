class RewardService:
    def Redeem(
        self,
        request,
        context,
    ):
        reward = reward_repository.find(
            request.reward_code
        )
        wallet_repository.add_points(
            request.account_id,
            reward["points"],
        )

        return {
            "points": reward["points"],
        }
