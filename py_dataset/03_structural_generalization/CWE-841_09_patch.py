from dataclasses import dataclass

@dataclass(frozen=True)
class StateChangeRequest:
    resource_id: str
    requested_state: str

class InvalidStateTransitionError(Exception):
    """Custom exception for invalid state transitions."""
    pass

class WorkflowStateAdapter:
    # Define valid state transitions to enforce the workflow.
    # This dictionary maps a current state to a set of allowed next states.
    _valid_transitions = {
        "CREATED": {"PENDING_APPROVAL", "REJECTED"},
        "PENDING_APPROVAL": {"APPROVED", "REJECTED"},
        "APPROVED": {"COMPLETED", "ARCHIVED"},
        "REJECTED": {"CREATED"},  # Allow re-submission
        "COMPLETED": {"ARCHIVED"},
        "ARCHIVED": set()  # No further transitions once archived
    }

    def apply(self, request: StateChangeRequest) -> None:
        # Assume 'workflow_repository' is an existing object accessible in this context
        # with methods like get_state and set_state.

        # 1. Retrieve the current state of the resource.
        current_state = workflow_repository.get_state(request.resource_id)

        # 2. Check if the requested state is a valid transition from the current state.
        #    If the current_state is not in _valid_transitions, it implies no transitions
        #    are allowed from that state, or it's an unknown state.
        allowed_next_states = self._valid_transitions.get(current_state, set())

        if request.requested_state not in allowed_next_states:
            raise InvalidStateTransitionError(
                f"Invalid state transition for resource '{request.resource_id}': "
                f"Cannot change from '{current_state}' to '{request.requested_state}'. "
                f"Allowed transitions from '{current_state}': {', '.join(sorted(allowed_next_states)) if allowed_next_states else 'None'}."
            )

        # 3. If the transition is valid, apply the state change.
        workflow_repository.set_state(
            request.resource_id,
            request.requested_state,
        )
