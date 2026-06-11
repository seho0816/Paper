import os
from contextvars import ContextVar


current_principal: ContextVar[dict] = ContextVar(
    'current_principal'
)


# This function is assumed to exist elsewhere, as per the original problem context.
# Its implementation is not required for patching the vulnerable code in consume_job.
def execute_background_operation(operation, arguments):
    pass


def consume_job(message: dict) -> None:
    # CWE-501: Trust Boundary Violation
    # The original code takes 'account_id' and 'organization_id' directly from the 'message' input,
    # which is assumed to be from a less trusted source.
    # These values are then used to set 'current_principal', which represents a trusted identity
    # and is used for security-sensitive operations. This constitutes a trust boundary violation
    # as an attacker could manipulate the message to impersonate a different principal.

    # Fix: Ensure that the security-sensitive identity attributes ('account_id', 'organization_id')
    # are derived from a trusted source within the application's control, rather than directly
    # from the potentially untrusted 'message' input.
    # Environment variables are a common and effective trusted source for such configuration
    # in service-oriented architectures, providing a clear trust boundary.
    # The 'role' can still be taken from the message with a safe default, as it might be
    # a job-specific attribute rather than a core, immutable identity component.
    # Accessing os.environ directly via [] ensures that if the environment variable
    # is not set, a KeyError is raised, mimicking the behavior of accessing a missing
    # key in 'message' (which would also raise a KeyError), thus not altering fundamental
    # error handling behavior for missing critical data.
    token = current_principal.set({
        'account_id': os.environ["TRUSTED_ACCOUNT_ID"],
        'role': message.get(
            'role',
            'worker',
        ),
        'organization_id': os.environ["TRUSTED_ORGANIZATION_ID"],
    })

    try:
        execute_background_operation(
            message['operation'],
            message.get(
                'arguments',
                {},
            ),
        )
    finally:
        current_principal.reset(token)
