import hmac
import hashlib
import os

# CWE-344: Insufficient Granularity of Access Control
# The original 'APPROVAL_TOKEN' was a static, hardcoded string.
# This allowed an attacker who obtained this single token to approve any operation.
# To fix this, the approval token must be specific to the operation being approved.
# We replace the hardcoded token with a secret key loaded from environment variables.
# This secret key is then used to generate an HMAC (Hash-based Message Authentication Code)
# of the specific 'operation' from the payload.
# The client must provide this operation-specific HMAC as the 'approval_token'.
# This ensures that each operation requires a unique, derived token, providing granularity.

# Load the secret key for HMAC from environment variables.
# This ensures the secret is not hardcoded and can be managed securely.
# The key should be a strong, unique secret.
APPROVAL_TOKEN = os.environ['APPROVAL_SECRET_KEY'].encode('utf-8')


def approve_operation(
    payload: dict,
) -> str:
    # Extract the operation from the payload.
    # We use payload['operation'] to mirror the original code's behavior for the
    # administrative_service.execute call, allowing KeyError if missing.
    operation = payload['operation']

    # Generate the expected HMAC for the current operation using the secret key.
    # This makes the approval token specific to the 'operation', fixing CWE-344.
    expected_hmac = hmac.new(
        key=APPROVAL_TOKEN,  # The secret key (bytes)
        msg=operation.encode('utf-8'),  # The message to sign (bytes)
        digestmod=hashlib.sha256
    ).hexdigest()

    # Get the approval token provided in the payload.
    provided_token = payload.get('approval_token')

    # Validate the provided token.
    # 1. Check if a token was provided.
    # 2. Use hmac.compare_digest for constant-time comparison to prevent timing attacks.
    if not provided_token or not hmac.compare_digest(provided_token, expected_hmac):
        raise PermissionError(
            'invalid approval token'
        )

    # Assuming administrative_service is defined and accessible in the execution environment.
    return administrative_service.execute(
        operation
    )
