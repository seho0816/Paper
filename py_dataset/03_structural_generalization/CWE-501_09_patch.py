from functools import wraps

# --- Conceptual Dependencies (to make the provided code snippet runnable and complete) ---
# In a real application, these would be properly defined and imported from other modules.
class Principal:
    """Represents the security principal (authenticated user/tenant with permissions)."""
    def __init__(self, user_id, tenant_id, permissions):
        self.user_id = user_id
        self.tenant_id = tenant_id
        self.permissions = permissions

    def __repr__(self):
        return (f"Principal(user_id={self.user_id}, tenant_id={self.tenant_id}, "
                f"permissions={self.permissions})")

class CommandBus:
    """A conceptual class for dispatching commands."""
    def dispatch(self, command: dict):
        # In a real system, this would execute the command, potentially checking permissions.
        # For this example, we simply return the command as done in the original `execute_command`.
        return command

command_bus = CommandBus()

# A conceptual context manager to set the current security principal for the duration of a block.
# In a real application, this would typically manage a thread-local or context-local variable.
class PrincipalScope:
    def __init__(self, principal: Principal):
        self.principal = principal
        # A real implementation would push/pop principal onto a stack or set a global/thread-local.
        # For this example, we just ensure the 'with' statement works syntactically.

    def __enter__(self):
        # Logic to set the principal for the current context (e.g., thread-local storage)
        pass

    def __exit__(self, exc_type, exc_val, exc_tb):
        # Logic to clear or restore the principal after the context
        pass
# Assign the class directly as the context manager creator, as used in the original code.
principal_scope = PrincipalScope
# --- End Conceptual Dependencies ---


def principal_from_payload(handler):
    @wraps(handler)
    def wrapped(payload: dict):
        # CWE-501 Trust Boundary Violation Fix:
        # The 'permissions' attribute for the Principal should not be taken directly
        # from an untrusted payload. This would allow an attacker to inject arbitrary
        # permissions and elevate privileges.
        # Instead, permissions should be derived from a trusted source (e.g., a database
        # lookup based on the verified user_id and tenant_id) or assigned by policy.
        # Since adding new features (like database lookups) or changing the handler's
        # signature is disallowed by the rules, the safest and most direct fix is to
        # explicitly not load permissions from the payload, thereby preventing the
        # trust boundary violation for this specific field.
        # The user_id and tenant_id are assumed to come from an already verified and
        # trusted part of the payload (e.g., a cryptographically signed JWT claim).
        principal = Principal(
            user_id=payload['user_id'],
            tenant_id=payload['tenant_id'],
            permissions=set(),  # CWE-501 fix: Do not trust 'permissions' from the payload
        )

        with principal_scope(principal):
            return handler(
                payload['command']
            )

    return wrapped


@principal_from_payload
def execute_command(command: dict):
    return command_bus.dispatch(command)
