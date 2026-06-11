from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class UserRecord:
    user_id: str
    email: str
    password_hash: str
    recovery_answer: str
    internal_notes: str


# Assuming 'database' is an external dependency or defined elsewhere in the application.
# Its implementation is not part of the fix scope.
# For example:
# class Database:
#     def load_user(self, user_id: str) -> UserRecord:
#         # Placeholder for actual database logic
#         if user_id == "user123":
#             return UserRecord(
#                 user_id="user123",
#                 email="user@example.com",
#                 password_hash="hashed_password_abc",
#                 recovery_answer="secret_answer",
#                 internal_notes="sensitive_internal_data"
#             )
#         raise ValueError("User not found")
#
# database = Database()


class UserRepository:
    def find(
        self,
        user_id: str,
    ) -> UserRecord:
        return database.load_user(
            user_id,
        )


class UserQueryService:
    def __init__(
        self,
        repository: UserRepository,
    ) -> None:
        self._repository = repository

    def get_profile(
        self,
        user_id: str,
    ) -> dict:
        record = self._repository.find(
            user_id,
        )

        # CWE-200 fix: Exclude sensitive fields from the returned dictionary
        # to prevent exposure of internal notes, password hashes, or recovery answers.
        profile_data = asdict(record)

        # Remove sensitive fields before returning the profile data.
        del profile_data["password_hash"]
        del profile_data["recovery_answer"]
        del profile_data["internal_notes"]

        return profile_data
