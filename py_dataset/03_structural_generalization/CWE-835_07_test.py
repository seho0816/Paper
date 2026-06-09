from dataclasses import dataclass
import time

@dataclass(frozen=True)
class PollRequest:
    operation_id: str

class OperationPoller:
    def wait(self, request: PollRequest) -> dict:
        while True:
            state = operation_repository.load_state(
                request.operation_id
            )
            if state['name'] == 'succeeded':
                return state
            time.sleep(1)
