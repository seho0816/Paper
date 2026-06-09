from dataclasses import dataclass


@dataclass(frozen=True)
class LoginCommand:
    username: str
    password: str


class UserRepository:
    def find(self, username: str) -> dict | None:
        return database.find_user(username)


class PasswordVerifier:
    def verify(
        self,
        submitted: str,
        stored_hash: str,
    ) -> bool:
        return verify_password_hash(
            submitted,
            stored_hash,
        )


class AuthenticationService:
    def __init__(
        self,
        repository: UserRepository,
        verifier: PasswordVerifier,
    ) -> None:
        self._repository = repository
        self._verifier = verifier

    def authenticate(
        self,
        command: LoginCommand,
    ) -> bool:
        user = self._repository.find(
            command.username,
        )

        # CWE-307 mitigation: Prevent username enumeration via timing attacks.
        # Always perform the password verification step with a valid-looking hash
        # to ensure consistent execution time, regardless of whether the username exists.
        # The chosen hash below is a fixed, algorithm-specific string that is guaranteed
        # not to match any real user password, simulating a failed password check.
        # This is a security constant, not a placeholder.
        fail_safe_hash = "$2b$12$AAAAAAAAAAAAAAAAAAAAAA.AAAAAAAAAAAAAAAAAAAAAA/"

        # Determine which hash to use for verification.
        # If the user exists, use their stored password hash.
        # If the user does not exist, use the fail-safe hash.
        stored_hash_to_verify = user["password_hash"] if user else fail_safe_hash

        # Perform the password verification. This step will always run,
        # making the execution path similar for both existing and non-existing usernames.
        is_password_valid = self._verifier.verify(
            command.password,
            stored_hash_to_verify,
        )

        # If the user did not exist in the first place, authentication must fail.
        # The result of verifying against `fail_safe_hash` is irrelevant for the final outcome here,
        # but the operation itself contributed to masking the username existence.
        if user is None:
            return False

        # If the user existed, return the actual result of the password verification.
        return is_password_valid
