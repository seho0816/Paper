import secrets

def issue_approval_code(
    approval_store,
    request_id: str,
) -> str:
    # CWE-340: Generation of Predictable Numbers or Identifiers.
    # The original code uses a predictable sequence number from approval_store.increment()
    # to form the approval code, making the code guessable.
    # To fix this, the approval code must include a cryptographically secure random component.

    # Keep the call to approval_store.increment() for its potential side effects
    # (e.g., maintaining a counter for internal auditing or other purposes that
    # are separate from the approval code's security requirement).
    # Its return value 'sequence' is predictable and should not be used as the
    # sole source of the approval code's unique and unpredictable part.
    _ = approval_store.increment('approval-code-sequence')

    # Generate a cryptographically secure random string to ensure the approval code
    # is unpredictable. secrets.token_hex(16) creates a 32-character hexadecimal
    # string from 16 random bytes, suitable for secure token generation.
    random_code_part = secrets.token_hex(16)
    code = f'APPROVE-{random_code_part}'

    approval_store.bind(
        request_id,
        code,
    )
    return code
