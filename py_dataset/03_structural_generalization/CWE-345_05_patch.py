import json
from dataclasses import dataclass
import hmac
import hashlib
import os


@dataclass(frozen=True)
class WebhookRequest:
    raw_body: bytes
    signature: str


class WebhookDecoder:
    # Lazily load the secret key from environment variable to adhere to
    # "maintain class structure and signatures" rule by not altering __init__ implicitly.
    _secret_key: bytes | None = None

    def _get_secret_key(self) -> bytes:
        """
        Retrieves the webhook secret key from the environment variable.
        Raises a RuntimeError if the key is not set.
        """
        if self._secret_key is None:
            key_str = os.environ.get("WEBHOOK_SECRET_KEY")
            if not key_str:
                raise RuntimeError("WEBHOOK_SECRET_KEY environment variable is not set or empty.")
            self._secret_key = key_str.encode('utf-8')
        return self._secret_key

    def decode(
        self,
        request: WebhookRequest,
    ) -> dict:
        # Retrieve the secret key for HMAC calculation
        secret_key = self._get_secret_key()

        # Calculate the expected signature using HMAC-SHA256.
        # request.raw_body is expected to be bytes.
        expected_signature = hmac.new(
            key=secret_key,
            msg=request.raw_body,
            digestmod=hashlib.sha256,
        ).hexdigest()

        # Compare the computed signature with the one provided in the request.
        # Use hmac.compare_digest to prevent timing attacks.
        if not hmac.compare_digest(expected_signature, request.signature):
            raise ValueError("Invalid webhook signature")

        # If the signature is valid, proceed to decode the JSON body.
        return json.loads(
            request.raw_body,
        )


class OrderWebhookService:
    def __init__(
        self,
        decoder: WebhookDecoder,
    ) -> None:
        self._decoder = decoder

    def handle(
        self,
        request: WebhookRequest,
    ) -> None:
        event = self._decoder.decode(
            request,
        )

        if event["type"] == "order.refunded":
            # This function (mark_order_refunded) is assumed to be defined elsewhere
            # and its call is part of the original structure.
            mark_order_refunded(
                event["order_id"],
            )
