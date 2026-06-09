import json
import os
import hmac
import hashlib


def deploy_gateway_policy(service_description: str) -> dict:
    POLICY_VERIFICATION_SECRET = os.environ.get("POLICY_VERIFICATION_SECRET")

    if not POLICY_VERIFICATION_SECRET:
        # In a real application, this should raise a configuration error
        # or log a critical failure, as policy integrity cannot be verified.
        # For this exercise, we assume the environment variable will be set.
        # If not set, the policy would be processed without verification,
        # which defeats the purpose of the fix.
        raise RuntimeError("POLICY_VERIFICATION_SECRET environment variable not set. Cannot verify policy integrity.")

    POLICY_VERIFICATION_SECRET_BYTES = POLICY_VERIFICATION_SECRET.encode('utf-8')

    output = model_client.generate_gateway_policy(
        service_description
    )

    try:
        # Assume the 'output' from model_client is a JSON string
        # containing both the actual policy data and an HMAC signature for integrity verification.
        # Expected structure: {"policy": {...}, "hmac_signature": "..."}
        raw_output_data = json.loads(output)
    except json.JSONDecodeError:
        raise ValueError("Invalid JSON format received from policy generation service.")

    if not isinstance(raw_output_data, dict) or "policy" not in raw_output_data or "hmac_signature" not in raw_output_data:
        raise ValueError("Policy output missing 'policy' or 'hmac_signature' fields for verification. Malformed policy or missing integrity check.")

    policy_data = raw_output_data["policy"]
    received_signature = raw_output_data["hmac_signature"]

    # To ensure consistent hashing, canonicalize the policy_data JSON string.
    # This involves sorting keys and removing unnecessary whitespace.
    canonical_policy_string = json.dumps(policy_data, sort_keys=True, separators=(',', ':'))

    # Calculate the expected HMAC signature
    expected_signature = hmac.new(
        POLICY_VERIFICATION_SECRET_BYTES,
        canonical_policy_string.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()

    # Compare the received signature with the expected signature in a constant-time manner
    # to prevent timing attacks. This fixes CWE-1426 by ensuring the policy's integrity
    # and authenticity before it is applied.
    if not hmac.compare_digest(expected_signature, received_signature):
        raise ValueError("Policy integrity check failed: Invalid HMAC signature. Policy may have been tampered with or is from an untrusted source.")

    # If verification passes, the policy is trusted.
    policy = policy_data
    api_gateway.replace_authorization_policy(
        policy
    )
    return policy
