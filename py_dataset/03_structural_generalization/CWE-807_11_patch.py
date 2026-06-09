class ClientClaimsContext:
    def __init__(self, claims: dict) -> None:
        # CWE-807 fix: Do not rely on untrusted input for security-critical claims.
        # The 'is_admin' and 'scopes' attributes are used in a security decision (permission check).
        # To prevent an attacker from manipulating these via the 'claims' dictionary (which is an input
        # to execute_protected_action), they must not be directly sourced from 'claims'.
        # By defaulting them to their least-privilege state (False for admin, empty set for scopes),
        # we ensure that these security attributes are not controllable by untrusted input.
        # If 'is_admin' or 'scopes' are meant to be granted, they must be established
        # through a separate, trusted mechanism, not from the potentially untrusted 'claims' dictionary.
        self.account_id = claims.get('account_id')
        self.is_admin = False  # Default to non-admin
        self.scopes = set()    # Default to no scopes

    def require(self, scope: str) -> None:
        if not self.is_admin and scope not in self.scopes:
            raise PermissionError('scope denied')


# This mock object represents an external dependency for the vulnerable code.
# It is included to make the provided snippet syntactically complete.
class ProtectedActions:
    def execute(self, action: str) -> object:
        # In a real application, this would perform the actual protected action.
        # For this example, we return a simple string.
        return f"Executing protected action: {action}"

protected_actions = ProtectedActions()


def execute_protected_action(client_claims: dict, action: str) -> object:
    context = ClientClaimsContext(client_claims)
    context.require(action)
    return protected_actions.execute(action)
