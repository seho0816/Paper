import base64
import json
import os
import hmac
import hashlib
from dataclasses import dataclass


@dataclass(frozen=True)
class Identity:
    subject: str
    role: str


class TokenDecoder:
    def decode_payload(
        self,
        token: str,
    ) -> dict:
        parts = token.split(".")
        if len(parts) != 3:
            raise ValueError("Invalid token format: Expected 3 parts (header.payload.signature)")

        header_segment, payload_segment, signature_segment = parts

        # Base64url-decode requires padding. The original code adds padding before decode,
        # and base64.urlsafe_b64decode tolerates strings without padding.
        # We will add padding to ensure consistency with the original code's approach.
        def pad_segment(segment: str) -> str:
            return segment + "=" * (-len(segment) % 4)

        padded_header = pad_segment(header_segment)
        padded_payload = pad_segment(payload_segment)
        padded_signature = pad_segment(signature_segment)

        # 1. Decode header to determine the algorithm (alg)
        try:
            header = json.loads(
                base64.urlsafe_b64decode(padded_header)
            )
        except (json.JSONDecodeError, ValueError) as e:
            raise ValueError("Invalid header segment") from e

        alg = header.get("alg")
        # For simplicity and adhering to "no new features", we'll only support HS256.
        # In a real-world scenario, a proper JWT library would handle various algorithms.
        if alg != "HS256":
            raise ValueError(f"Unsupported or missing algorithm: {alg}. Only HS256 is supported.")

        # 2. Retrieve the secret key for signature verification
        # As per rule 7, use os.environ for configuration values to avoid changing signatures.
        try:
            secret_key = os.environ["JWT_SECRET_KEY"].encode('utf-8')
        except KeyError:
            raise ValueError("JWT_SECRET_KEY environment variable not set.")

        # 3. Verify the signature
        # The signing input is the base64url-encoded header and payload concatenated with a dot.
        signing_input = f"{header_segment}.{payload_segment}".encode('utf-8')
        
        # Calculate the expected signature
        try:
            # For HS256, use HMAC with SHA256.
            expected_signature_bytes = hmac.new(secret_key, signing_input, hashlib.sha256).digest()
        except Exception as e:
            raise ValueError("Error calculating signature") from e

        # Decode the provided signature segment from the token
        try:
            decoded_signature_bytes = base64.urlsafe_b64decode(padded_signature)
        except ValueError as e:
            raise ValueError("Invalid signature segment") from e
        
        # Compare the calculated signature with the provided signature using a constant-time comparison
        if not hmac.compare_digest(expected_signature_bytes, decoded_signature_bytes):
            raise ValueError("Invalid signature")

        # Signature is valid, now safely decode and return the payload
        try:
            return json.loads(
                base64.urlsafe_b64decode(
                    padded_payload,
                )
            )
        except (json.JSONDecodeError, ValueError) as e:
            raise ValueError("Invalid payload segment") from e


class IdentityService:
    def __init__(
        self,
        decoder: TokenDecoder,
    ) -> None:
        self._decoder = decoder

    def load(
        self,
        token: str,
    ) -> Identity:
        payload = self._decoder.decode_payload(
            token,
        )

        return Identity(
            subject=str(payload["sub"]),
            role=str(payload["role"]),
        )
