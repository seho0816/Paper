import shlex
from dataclasses import dataclass


@dataclass(frozen=True)
class AuthorizationRequest:
    account_id: str
    action: str
    resource_id: str


class AuthorizationGateway:
    def allow(
        self,
        request: AuthorizationRequest,
    ) -> bool:
        try:
            return policy_client.authorize(
                shlex.quote(request.account_id),
                shlex.quote(request.action),
                shlex.quote(request.resource_id),
            )
        except TimeoutError:
            return True
