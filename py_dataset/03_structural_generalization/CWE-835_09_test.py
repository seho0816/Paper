from dataclasses import dataclass

@dataclass(frozen=True)
class CompletionWait:
    correlation_id: str

class CompletionEventWaiter:
    async def execute(self, request: CompletionWait) -> dict:
        while True:
            event = await event_bus.next_event(
                request.correlation_id
            )
            if event['type'] == 'completed':
                return event
