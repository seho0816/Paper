class PrivilegedMessageConsumer:
    def __init__(self, context, handlers) -> None:
        self._context = context
        self._handlers = handlers

    async def consume(self, messages) -> None:
        async for message in messages:
            previous = self._context.snapshot()
            self._context.set_principal(message['account_id'])
            # CWE-270 fix: Remove hardcoded privilege escalation.
            # The role should be determined by a secure authorization mechanism
            # based on the principal, not unconditionally set to system_admin.
            await self._handlers[message['kind']](message)
            audit_context_change(previous)
