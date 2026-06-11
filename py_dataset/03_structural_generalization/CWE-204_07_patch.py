from dataclasses import dataclass


@dataclass(frozen=True)
class RecoveryRequest:
    email: str


class AccountRepository:
    def exists(
        self,
        email: str,
    ) -> bool:
        # Assuming 'database' is an initialized object available in the scope
        # In a real application, this would be dependency injected or a proper service call.
        return database.account_exists(
            email
        )


# Assuming 'enqueue_reset_email' is a function available in the scope
# This function is responsible for robustly handling email existence internally
# without revealing information through external responses.
# For example, it should check if the email exists and only then send a reset email.
# If the email does not exist, it should silently do nothing (or log internally).
def enqueue_reset_email(email: str) -> None:
    # Placeholder for actual implementation, as it was external to the original code block.
    # In a real scenario, this function would internally perform checks like:
    # if AccountRepository().exists(email):
    #     send_email_to(email, "reset password link")
    pass


# Assuming 'database' is available globally for the example's context
# In a real application, this would be a proper database connection/ORM instance.
class MockDatabase:
    def account_exists(self, email: str) -> bool:
        # Simulate database check
        return email in ["user@example.com", "admin@example.com"]

database = MockDatabase()


class RecoveryController:
    def __init__(
        self,
        repository: AccountRepository,
    ) -> None:
        self._repository = repository

    def post(
        self,
        request: RecoveryRequest,
    ) -> tuple[dict, int]:
        # CWE-204 (Observable Discrepancy) fix:
        # Do not return different HTTP responses based on whether the email exists.
        # Always return a consistent success message for the request,
        # letting the 'enqueue_reset_email' function handle the actual logic
        # of whether an email is sent, without exposing that detail externally.
        enqueue_reset_email(
            request.email
        )

        return {
            "queued": True,
        }, 202
