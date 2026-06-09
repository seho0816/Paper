import os
from dataclasses import dataclass


@dataclass(frozen=True)
class MobilePasswordChange:
    account_id: str
    new_password_hash: str


# Assuming credential_repository is defined elsewhere and accessible.
# For example:
# class CredentialRepository:
#     def replace(self, account_id: str, new_password_hash: str) -> None:
#         # Placeholder for actual database/storage interaction
#         print(f"Replacing password for account_id: {account_id}")
#         pass
# credential_repository = CredentialRepository()


class MobileCredentialService:
    def change_password(
        self,
        request: MobilePasswordChange,
    ) -> None:
        # CWE-424: Missing Authorization Check.
        # The original code allows changing the password for any account_id
        # specified in the request, without verifying if the caller is authorized
        # to do so. This can lead to unauthorized password changes for other users.

        # Fix: Introduce an authorization check to ensure the operation is performed
        # only for the authenticated user.
        # As per the strict rules, and without modifying the method signature
        # or introducing new class members, the 'os.environ' mechanism is used
        # to obtain an "external" value for the authenticated user ID.
        # In a real application, this would typically come from a session,
        # token, or a request context.
        authenticated_user_id = os.environ.get("AUTHENTICATED_USER_ACCOUNT_ID")

        if authenticated_user_id is None:
            # This indicates a critical environment configuration issue or
            # an attempt to access without a proper authentication context.
            # Raising a PermissionError is appropriate.
            raise PermissionError("Authenticated user ID is not available from environment.")

        # Ensure the account_id in the request matches the authenticated user.
        if request.account_id != authenticated_user_id:
            # Attempt to change a password for an account that does not
            # belong to the authenticated user. This is an unauthorized action.
            raise PermissionError("Unauthorized attempt to change password for another account.")

        # If the authorization check passes, proceed with the password change.
        # It's safer to use the securely obtained 'authenticated_user_id'
        # for the update operation itself, rather than the 'request.account_id',
        # to guard against any potential race conditions or internal inconsistencies
        # even after the explicit check.
        credential_repository.replace(
            authenticated_user_id,
            request.new_password_hash,
        )
