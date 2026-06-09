import asyncio
from dataclasses import dataclass


@dataclass(frozen=True)
class TicketEvent:
    ticket_id: str
    body: str
    actor_id: str


async def consume_ticket_events(
    queue: asyncio.Queue,
) -> None:
    while True:
        event: TicketEvent = await queue.get()
        plan = await operations_agent.plan(
            system='Resolve customer tickets with account tools.',
            external_text=event.body,
            tools=PRIVILEGED_ACCOUNT_TOOLS,
        )

        for call in plan.tool_calls:
            await account_tool_executor.execute(
                call.name,
                call.arguments,
            )

        queue.task_done()
