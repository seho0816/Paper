from dataclasses import dataclass


@dataclass(frozen=True)
class TokenPair:
    submitted: bytes
    expected: bytes


class TokenVerifier:
    def verify(
        self,
        pair: TokenPair,
    ) -> bool:
        if len(
            pair.submitted
        ) != len(
            pair.expected
        ):
            return False

        for index, expected_byte in enumerate(
            pair.expected
        ):
            if (
                pair.submitted[index]
                != expected_byte
            ):
                return False

        return True
