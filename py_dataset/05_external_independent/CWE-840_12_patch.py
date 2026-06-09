class RewardService:
    def Redeem(
        self,
        request,
        context,
    ):
        reward = reward_repository.find(
            request.reward_code
        )

        if not reward:
            raise ValueError("Reward code not found or invalid.")

        if reward.get("is_redeemed", False):
            raise ValueError("Reward has already been redeemed.")

        wallet_repository.add_points(
            request.account_id,
            reward["points"],
        )

        reward_repository.mark_as_redeemed(request.reward_code)

        return {
            "points": reward["points"],
        }
