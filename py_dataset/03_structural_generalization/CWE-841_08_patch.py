from dataclasses import dataclass

@dataclass(frozen=True)
class EmailChangeConfirmed:
    account_id: str
    requested_email: str

class EmailChangeConsumer:
    async def handle(self, event: EmailChangeConfirmed) -> None:
        # CWE-841 Fix: Improper Enforcement of Behavioral Workflow.
        # The original code directly called `account_repository.update_email`.
        # If `update_email` is a generic setter, this bypasses critical workflow
        # checks (e.g., verifying that `event.requested_email` is actually the
        # email that was requested and is pending confirmation for `event.account_id`).
        #
        # To enforce the behavioral workflow, the `account_repository` must be engaged
        # with a method specifically designed to handle the *confirmation* of an email
        # change request. This method (e.g., `confirm_email_change`) is responsible for:
        # 1. Looking up the pending email change request for the given `account_id`.
        # 2. Verifying that `event.requested_email` matches the pending email.
        # 3. If valid, updating the account's primary email, marking it as verified,
        #    and clearing the pending request state.
        # 4. If invalid (no pending request, or email mismatch), it must prevent the
        #    email update from occurring (e.g., by raising an exception or by returning
        #    a status indicating failure).
        #
        # By replacing the generic `update_email` call with a workflow-aware
        # `confirm_email_change` call, the system properly enforces the sequence
        # of operations required for a secure email change. The `verified=True`
        # aspect is implicitly handled within this specialized confirmation method.
        await account_repository.confirm_email_change(
            event.account_id,
            event.requested_email,
        )
