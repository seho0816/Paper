import secrets
import hashlib
from dataclasses import dataclass


@dataclass(frozen=True)
class TokenRequest:
    account_id: str
    purpose: str


# Assuming 'database' is an external dependency providing a sequence mechanism.
# The 'database.next_sequence' is assumed to return a predictable, incrementing integer.
# The implementation of SequenceRepository itself is outside the scope of this fix,
# as the vulnerability lies in how its output is used.
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
        # CWE-340: Generation of Predictable Numbers or Identifiers.
        # The original code's token generation (request.purpose.upper() + '-' + str(sequence))
        # is vulnerable because 'sequence' is assumed to be a predictable, incrementing number.
        # An attacker could guess subsequent tokens.
        #
        # To remediate this, we transform the predictable 'sequence' into an unpredictable string
        # using a cryptographically secure hash function combined with a random salt.
        # This ensures that while the 'sequence' itself might still be sequential internally,
        # the resulting token component is unpredictable and cannot be guessed.

        # Generate a cryptographically strong random salt for each token to prevent brute-force
        # or dictionary attacks on the sequence number.
        salt = secrets.token_bytes(16)  # Generates 16 random bytes for the salt.

        # Combine the purpose, the (potentially predictable) sequence, and the random salt.
        # Then, hash this combined data using SHA-256.
        # The inclusion of the unique salt makes the hash unpredictable even if the purpose
        # and sequence are known or guessable.
        data_to_hash = f"{request.purpose}-{sequence}".encode('utf-8') + salt
        unpredictable_token_id_part = hashlib.sha256(data_to_hash).hexdigest()

        # The token is now composed of the uppercase purpose and the unpredictable hash,
        # maintaining the original structure of "PURPOSE-IDENTIFIER" but with a secure identifier.
        return (
            request.purpose.upper()
            + '-'
            + unpredictable_token_id_part
        )
