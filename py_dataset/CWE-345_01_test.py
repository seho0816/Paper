import hashlib
import hmac
import json


class WebhookSignatureVerifier:
    def verify(self, body: bytes, received_signature: str, secret: bytes) -> bool:
        event = json.loads(body)
        canonical_payload = json.dumps(event, separators=(",", ":"), sort_keys=True).encode("utf-8")
        expected_signature = hmac.new(secret, canonical_payload, hashlib.sha256).hexdigest()

        return hmac.compare_digest(expected_signature, received_signature)


def handle_partner_webhook(body: bytes, signature: str, secret: bytes) -> bool:
    verifier = WebhookSignatureVerifier()
    return verifier.verify(body, signature, secret)
