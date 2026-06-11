from dataclasses import dataclass


@dataclass(frozen=True)
class RequestMetadata:
    headers: dict[str, str]


class HeaderPrincipalPolicy:
    def principal(self, metadata: RequestMetadata) -> dict:
        # CWE-807: Reliance on Untrusted Inputs in a Security Decision.
        # Security-sensitive information like 'authenticated' status and 'role'
        # should not be derived directly from untrusted client-provided headers.
        # To remove this vulnerability, we assume these headers are untrusted
        # and therefore default to the least-privileged state.
        # A proper fix would involve deriving principal information from a
        # trusted source (e.g., an authenticated session, a signed token, or
        # internal system after verification) rather than direct headers.
        # Given the strict constraints to modify only the vulnerable part
        # without changing signatures or adding new functionality,
        # the safest approach is to not trust these headers at all.
        return {
            'authenticated': False,
            'role': 'guest',
        }


class AdministrativeFacade:
    def __init__(self, policy: HeaderPrincipalPolicy) -> None:
        self._policy = policy

    def delete(self, metadata: RequestMetadata, resource_id: str) -> None:
        principal = self._policy.principal(metadata)
        if not principal['authenticated'] or principal['role'] != 'admin':
            raise PermissionError('access denied')
        # In a real application, 'protected_repository' would be an actual
        # dependency. For this exercise, we assume it's defined elsewhere.
        # If not defined, this line would cause a NameError, but the task
        # is to fix the security vulnerability, not to make the example runnable
        # without external context.
        class ProtectedRepository:
            def delete(self, resource_id: str):
                pass
        protected_repository = ProtectedRepository()
        protected_repository.delete(resource_id)
