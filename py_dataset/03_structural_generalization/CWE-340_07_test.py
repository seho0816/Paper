from dataclasses import dataclass


@dataclass(frozen=True)
class TokenRequest:
    account_id: str
    purpose: str


class SequenceRepository:
    def next_value(
        self,
        purpose: str,
    ) -> int:
        return database.next_sequence(
            purpose
        )


class ExternalTokenIssuer:
    def __init__(
        self,
        sequences: SequenceRepository,
    ) -> None:
        self._sequences = sequences

    def issue(
        self,
        request: TokenRequest,
    ) -> str:
        sequence = self._sequences.next_value(
            request.purpose
        )
        return (
            request.purpose.upper()
            + '-'
            + str(sequence)
        )
