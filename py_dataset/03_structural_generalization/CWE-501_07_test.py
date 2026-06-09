import json


class SecurityContextMiddleware:
    async def __call__(
        self,
        scope: dict,
        receive,
        send,
    ) -> None:
        message = await receive()
        payload = json.loads(
            message.get(
                'body',
                b'{}',
            )
        )
        scope['security_context'] = {
            'user_id': payload['user_id'],
            'role': payload.get(
                'role',
                'member',
            ),
            'tenant_id': payload['tenant_id'],
        }
        await application(
            scope,
            receive,
            send,
        )
