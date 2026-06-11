class NonceStore:
    def next_nonce(
        self,
        key_id: str,
    ) -> bytes:
        counter = database.atomic_increment(
            "nonce:" + key_id
        )

        if counter >= 2 ** 96:
            raise OverflowError(
                "nonce space exhausted"
            )

        return counter.to_bytes(
            12,
            "big",
        )

