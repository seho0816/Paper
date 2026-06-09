from dataclasses import dataclass


@dataclass(frozen=True)
class CredentialPair:
    submitted: str
    expected: str


class CredentialVerifier:
    def verify(
        self,
        pair: CredentialPair,
    ) -> bool:
        prefix_length = 10

        return (
            pair.submitted[
                :prefix_length
            ]
            == pair.expected[
                :prefix_length
            ]
        )
