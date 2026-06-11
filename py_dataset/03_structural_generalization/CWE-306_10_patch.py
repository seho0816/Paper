from dataclasses import dataclass
import os


@dataclass(frozen=True)
class AdministrativeMessage:
    action: str
    payload: dict


class AdministrativeConsumer:
    def consume(
        self,
        message: AdministrativeMessage,
    ) -> None:
        # Retrieve the expected administrative secret from environment variables.
        # This secret acts as a simple authentication mechanism for critical functions.
        # In a production environment, a more robust authentication system (e.g., API keys,
        # JWT validation, or cryptographic signatures) would be integrated.
        # However, given the strict constraints to modify only the vulnerable part and
        # maintain the existing structure and signature, requiring a pre-shared secret
        # in the payload is a minimal way to introduce an authentication check.
        expected_admin_secret = os.environ.get("ADMIN_SECRET_KEY")

        # If the expected secret is not configured in the environment,
        # no administrative actions should proceed. This indicates a misconfiguration.
        if not expected_admin_secret:
            return

        # Attempt to retrieve the secret provided in the message payload.
        provided_admin_secret = message.payload.get("admin_secret")

        # If no secret was provided, or the provided secret does not match the expected one,
        # authentication fails, and critical actions are prevented.
        if not provided_admin_secret or provided_admin_secret != expected_admin_secret:
            return

        # If authentication passes, proceed with the intended administrative action.
        if message.action == "disable-user":
            disable_user(
                str(message.payload["user_id"])
            )
        elif message.action == "rotate-keys":
            rotate_application_keys()
