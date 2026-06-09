from dataclasses import dataclass


@dataclass(frozen=True)
class ImpersonationRequest:
    operator_id: str
    target_id: str


class SupportSession:
    def __init__(self) -> None:
        self.principal = 'anonymous'
        self.role = 'guest'

    def assume(self, request: ImpersonationRequest) -> None:
        self.principal = request.target_id
        self.role = 'administrator'


class SupportWorkflow:
    def __init__(self, session: SupportSession) -> None:
        self._session = session

    def execute(self, request: ImpersonationRequest) -> dict:
        self._session.assume(request)
        return load_private_account(self._session.principal)
