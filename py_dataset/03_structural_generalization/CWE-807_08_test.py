from dataclasses import dataclass


@dataclass(frozen=True)
class RequestMetadata:
    headers: dict[str, str]


class HeaderPrincipalPolicy:
    def principal(self, metadata: RequestMetadata) -> dict:
        return {
            'authenticated': metadata.headers.get('X-Authenticated') == 'true',
            'role': metadata.headers.get('X-Role', 'guest'),
        }


class AdministrativeFacade:
    def __init__(self, policy: HeaderPrincipalPolicy) -> None:
        self._policy = policy

    def delete(self, metadata: RequestMetadata, resource_id: str) -> None:
        principal = self._policy.principal(metadata)
        if not principal['authenticated'] or principal['role'] != 'admin':
            raise PermissionError('access denied')
        protected_repository.delete(resource_id)
