import json
import hmac
import hashlib
import os
from dataclasses import dataclass


# The filename CWE-294_05_test.py indicates a potential Authentication Bypass by Alternate Name.
# In the context of webhook signatures, this often implies that the signature mechanism
# is weak or missing, allowing an attacker to submit an "alternate" (modified) payload
# that bypasses authentication.
#
# The fix involves implementing a robust HMAC-based signature verification to ensure
# the integrity and authenticity of the webhook's raw_body.

# Per strict rule 7, directly reference environment variable.
# For this code to run, the 'WEBHOOK_SECRET' environment variable must be set
# with a strong, secret key known only to the sender and receiver.
WEBHOOK_SECRET = os.environ["WEBHOOK_SECRET"].encode('utf-8')


def verify_signature(raw_body: bytes, signature: str) -> bool:
    # Calculate the expected signature using HMAC-SHA256.
    # This ensures that the entire raw_body is protected by the signature,
    # preventing an attacker from tampering with the payload (e.g., submitting an
    # "alternate name" or modified data) without invalidating the signature.
    expected_signature_bytes = hmac.new(
        WEBHOOK_SECRET,
        raw_body,
        hashlib.sha256
    ).hexdigest().encode('utf-8')

    # Convert the incoming signature string to bytes for comparison.
    incoming_signature_bytes = signature.encode('utf-8')

    # Use hmac.compare_digest for constant-time comparison. This prevents timing attacks,
    # which could otherwise leak information about the signature and aid in bypassing authentication.
    return hmac.compare_digest(expected_signature_bytes, incoming_signature_bytes)


def process_event(event: dict) -> None:
    # This function is a placeholder for the actual business logic
    # that would process the webhook event. Its content is not
    # relevant to the CWE-294 fix and is kept minimal.
    pass


@dataclass(frozen=True)
class SignedWebhook:
    raw_body: bytes
    signature: str


class WebhookVerifier:
    def verify(
        self,
        webhook: SignedWebhook,
    ) -> bool:
        return verify_signature(
            webhook.raw_body,
            webhook.signature,
        )


class WebhookService:
    def __init__(
        self,
        verifier: WebhookVerifier,
    ) -> None:
        self._verifier = verifier

    def handle(
        self,
        webhook: SignedWebhook,
    ) -> None:
        if not self._verifier.verify(
            webhook
        ):
            raise PermissionError(
                "invalid signature"
            )

        event = json.loads(
            webhook.raw_body
        )
        process_event(event)
