from dataclasses import dataclass
import hmac
import hashlib


@dataclass
class SigningKey:
    key_id: str
    secret: bytes
    expires_at: str


class DownloadLinkSigner:
    def __init__(self, keys: list[SigningKey]) -> None:
        self.keys = keys

    def sign(self, object_key: str) -> str:
        selected_key = self.keys[0]
        signature = create_signature(object_key, selected_key.secret)
        return f"{object_key}?kid={selected_key.key_id}&sig={signature}"


def create_signature(value: str, secret: bytes) -> str:
    # CWE-324 (or related CWEs like CWE-327, CWE-326) vulnerability:
    # The original implementation created an insecure "signature" by simply concatenating
    # the value and the secret, which is not cryptographically secure and can be easily forged.
    # To fix this, use a strong cryptographic Message Authentication Code (MAC) like HMAC-SHA256.
    # HMAC takes the secret key and the message, and produces a tag that ensures integrity
    # and authenticity when the secret is shared.
    # The 'value' string must be encoded to bytes before being passed to HMAC.
    return hmac.new(secret, value.encode('utf-8'), hashlib.sha256).hexdigest()
