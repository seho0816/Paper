from dataclasses import dataclass

@dataclass(frozen=True)
class CompletionWait:
    correlation_id: str

class CompletionEventWaiter:
    async def execute(self, request: CompletionWait) -> dict:
        # CWE-835 (Infinite Loop) fix: Introduce a maximum number of attempts
        # to prevent the loop from running indefinitely if the completion event is never received.
        MAX_ATTEMPTS = 100
        attempts = 0
        while attempts < MAX_ATTEMPTS:
            event = await event_bus.next_event(
                request.correlation_id
            )
            if event['type'] == 'completed':
                return event
            attempts += 1
        
        # If the loop finishes without returning, it means the event was not found
        # within the defined maximum attempts, preventing an infinite loop and
        # providing a clear error state.
        raise TimeoutError(
            f"Completion event for correlation_id='{request.correlation_id}' not received "
            f"after {MAX_ATTEMPTS} attempts."
        )
