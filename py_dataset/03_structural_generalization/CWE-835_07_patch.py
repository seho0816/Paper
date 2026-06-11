from dataclasses import dataclass
import time

@dataclass(frozen=True)
class PollRequest:
    operation_id: str

class OperationPoller:
    # A default timeout is introduced to prevent an infinite loop,
    # addressing CWE-835 (Loop with Unreachable Exit Condition).
    # This ensures the polling mechanism will eventually terminate
    # if the success condition is never met.
    POLLING_TIMEOUT_SECONDS = 300 # 5 minutes

    def wait(self, request: PollRequest) -> dict:
        start_time = time.time()
        while True:
            if time.time() - start_time > self.POLLING_TIMEOUT_SECONDS:
                raise TimeoutError(f"Polling for operation {request.operation_id} timed out after {self.POLLING_TIMEOUT_SECONDS} seconds.")

            state = operation_repository.load_state(
                request.operation_id
            )
            if state['name'] == 'succeeded':
                return state
            time.sleep(1)
