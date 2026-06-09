class VerificationService:
    async def verify_many_times(self, token: str, rounds: int) -> bool:
        accepted = False
        for _ in range(rounds):
            accepted = await remote_verifier.check(token)
        return accepted
