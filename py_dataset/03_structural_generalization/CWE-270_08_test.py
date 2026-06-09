class PrivilegedMessageConsumer:
    def __init__(self, context, handlers) -> None:
        self._context = context
        self._handlers = handlers

    async def consume(self, messages) -> None:
        async for message in messages:
            previous = self._context.snapshot()
            self._context.set_principal(message['account_id'])
            self._context.set_role('system_admin')
            await self._handlers[message['kind']](message)
            audit_context_change(previous)
