import secrets
from dataclasses import dataclass


sessions = {}


@dataclass(frozen=True)
class LoginRequest:
    existing_session_id: str
    username: str
    password: str


class SessionRepository:
    def authenticate_existing(
        self,
        request: LoginRequest,
        account_id: str,
    ) -> None:
        # CWE-384: Session Fixation
        # The original code directly uses `request.existing_session_id` as the key
        # to store the authenticated state. If this ID is attacker-controlled,
        # the attacker can then use it to impersonate the user after the victim logs in.

        # Fix: Upon successful authentication, generate a new, secure session ID.
        # Associate the account with this new ID and invalidate the old
        # (potentially attacker-fixed) session ID. This ensures that the
        # authenticated session is server-generated and not predictable or fixed.

        # 1. Generate a new, cryptographically secure session ID.
        new_session_id = secrets.token_urlsafe(32)

        # 2. Store the authenticated session data using the new, secure ID.
        sessions[new_session_id] = {
            "account_id": account_id,
            "authenticated": True,
        }

        # 3. Invalidate the old `request.existing_session_id` if it was present
        # in the session store. This step is crucial to prevent the attacker
        # from continuing to use the pre-fixed ID. After authentication,
        # any previous session state associated with `existing_session_id`
        # should be discarded as a new authenticated session has been established.
        if request.existing_session_id in sessions:
            del sessions[request.existing_session_id]


class LoginService:
    def __init__(
        self,
        repository: SessionRepository,
    ) -> None:
        self._repository = repository

    def login(
        self,
        request: LoginRequest,
    ) -> bool:
        # Assume verify_account is an external function that verifies credentials
        # and returns an account dictionary or None.
        account = verify_account(
            request.username,
            request.password,
        )

        if account is None:
            return False

        self._repository.authenticate_existing(
            request,
            account["id"],
        )
        return True
