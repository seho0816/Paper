from dataclasses import dataclass


@dataclass(frozen=True)
class IncidentContext:
    request_headers: dict
    session: dict
    account: dict


class IncidentReportAssembler:
    def build(self, context: IncidentContext) -> dict:
        # Define common sensitive keys for each category.
        # Using frozenset for efficient lookups and to indicate immutability.
        # Header keys are typically case-insensitive, so store them lowercase for comparison.
        SENSITIVE_HEADERS = frozenset([
            "authorization", "cookie", "set-cookie", "proxy-authorization",
            "x-api-key", "x-auth-token", "x-csrf-token",
        ])
        SENSITIVE_SESSION_KEYS = frozenset([
            "session_id", "_csrf_token", "api_key", "password_hash", "private_key",
            "access_token", "refresh_token", "auth_token", "encryption_key",
            "secret_key",
        ])
        SENSITIVE_ACCOUNT_KEYS = frozenset([
            "password", "ssn", "credit_card_number", "api_key", "token", "private_key",
            "secret_key", "bearer_token", "encryption_key", "mfa_secret",
            "client_secret", "refresh_token", "access_token",
        ])

        # Create new dictionaries, filtering out sensitive information.
        # This ensures that the original context object's data is not modified
        # and prevents sensitive data from being logged or exposed.

        # For headers, perform a case-insensitive check against the sensitive list.
        cleaned_headers = {
            k: v for k, v in context.request_headers.items()
            if k.lower() not in SENSITIVE_HEADERS
        }

        # For session data, perform a case-sensitive check.
        cleaned_session = {
            k: v for k, v in context.session.items()
            if k not in SENSITIVE_SESSION_KEYS
        }

        # For account data, perform a case-sensitive check.
        cleaned_account = {
            k: v for k, v in context.account.items()
            if k not in SENSITIVE_ACCOUNT_KEYS
        }

        return {
            "headers": cleaned_headers,
            "session": cleaned_session,
            "account": cleaned_account,
        }
