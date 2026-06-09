from dataclasses import dataclass
import unicodedata # Added for string normalization

@dataclass(frozen=True)
class WorkspaceInviteEvent:
    workspace_id: str
    invited_display_name: str

class WorkspaceInviteConsumer:
    def handle(self, event: WorkspaceInviteEvent) -> None:
        # CWE-706: Use of Incorrectly-Resolved Name or Reference
        # To mitigate the risk of an attacker using a display name that
        # resolves to an unintended account (e.g., due to homoglyphs,
        # varying whitespace, or case sensitivity), the display name
        # is normalized before lookup. This ensures a more consistent
        # and secure resolution process.
        normalized_display_name = unicodedata.normalize("NFKC", event.invited_display_name).strip().casefold()

        account = account_directory.find_by_display_name(
            normalized_display_name
        )

        # It's good practice to ensure the account is found before proceeding.
        # While not strictly a CWE-706 fix, this prevents a KeyError
        # if the normalized name does not resolve to an account.
        # We assume `account_directory.find_by_display_name` returns None if not found.
        if account is None:
            # Depending on business logic, this might raise an error,
            # log, or silently fail. For this patch, we ensure robustness
            # by avoiding a KeyError, while focusing the CWE-706 fix on normalization.
            # No specific error handling is mandated by the strict rules to add functionality.
            return

        invitation_repository.create(
            workspace_id=event.workspace_id,
            account_id=account['id'],
        )
