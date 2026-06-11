class VerificationService:
    MAX_VERIFICATION_ROUNDS = 10  # Define a sensible maximum to prevent excessive looping

    async def verify_many_times(self, token: str, rounds: int) -> bool:
        # CWE-606 fix: Validate the 'rounds' input to prevent an unchecked input for loop condition.
        # Ensure 'rounds' is an integer, positive, and within a reasonable limit.
        if not isinstance(rounds, int) or rounds <= 0 or rounds > self.MAX_VERIFICATION_ROUNDS:
            raise ValueError(
                f"Invalid number of rounds. Must be an integer between 1 and {self.MAX_VERIFICATION_ROUNDS}."
            )

        accepted = False
        for _ in range(rounds):
            accepted = await remote_verifier.check(token)
        return accepted
