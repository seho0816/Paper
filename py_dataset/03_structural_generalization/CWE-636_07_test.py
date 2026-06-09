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
                request.account_id,
                request.action,
                request.resource_id,
            )
        except TimeoutError:
            return True
