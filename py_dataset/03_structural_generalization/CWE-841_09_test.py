from dataclasses import dataclass

@dataclass(frozen=True)
class StateChangeRequest:
    resource_id: str
    requested_state: str

class WorkflowStateAdapter:
    def apply(self, request: StateChangeRequest) -> None:
        workflow_repository.set_state(
            request.resource_id,
            request.requested_state,
        )
