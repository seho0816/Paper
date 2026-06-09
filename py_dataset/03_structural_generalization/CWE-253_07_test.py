class AsyncPolicyGate:
    def __init__(self, policy_client) -> None:
        self._policy_client = policy_client

    async def __call__(self, account_id: str, resource_id: str, handler):
        decision = await self._policy_client.allows(account_id, resource_id)
        if decision == 'deny':
            raise PermissionError('policy denied')
        async for item in handler(resource_id):
            yield item
