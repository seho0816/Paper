import threading
from dataclasses import dataclass

# Assume identity_store and permission_repository are globally accessible or implicitly available in this scope.
# To address CWE-706 (Improper Synchronization), particularly a Time-of-Check to Time-of-Use (TOCTOU) vulnerability,
# we need to ensure that the alias-to-account_id mapping remains consistent between resolution and permission granting.
# A global lock is introduced to synchronize access to the identity store during the entire grant process,
# preventing concurrent modifications to the alias mapping that could lead to an incorrect account_id being used.
_identity_store_lock = threading.Lock()

@dataclass(frozen=True)
class PermissionGrant:
    project_id: str
    account_alias: str
    permission: str

class AccountReferenceResolver:
    def resolve(self, alias: str) -> str:
        # Access to identity_store.find_by_alias is now protected by the global lock
        # in the PermissionGrantService.grant method. This resolver itself doesn't need
        # to acquire the lock again, as the caller (PermissionGrantService) already holds it
        # for the entire check-and-use sequence, preventing TOCTOU.
        record = identity_store.find_by_alias(alias)
        # Added basic error handling for robustness, though not strictly part of CWE-706 fix,
        # it's good practice for dependency calls.
        if not record or 'account_id' not in record:
            raise ValueError(f"Alias '{alias}' not found or invalid record in identity store.")
        return record['account_id']

class PermissionGrantService:
    def __init__(self, resolver: AccountReferenceResolver) -> None:
        self._resolver = resolver

    def grant(self, request: PermissionGrant) -> None:
        # The CWE-706 vulnerability (TOCTOU) occurs if the alias-to-account_id mapping
        # in 'identity_store' changes between the call to '_resolver.resolve' (check)
        # and the call to 'permission_repository.grant' (use).
        # To fix this, we acquire a global lock that spans both operations, ensuring
        # atomicity of the alias resolution and permission granting with respect to
        # any concurrent changes to the identity store.
        with _identity_store_lock:
            account_id = self._resolver.resolve(request.account_alias)
            permission_repository.grant(
                request.project_id,
                account_id,
                request.permission,
            )
