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
        auth_context = scope.get('auth', {})
        scope['security_context'] = {
            'user_id': auth_context['user_id'],
            'role': auth_context.get(
                'role',
                'member',
            ),
            'tenant_id': auth_context['tenant_id'],
        }
        await application(
            scope,
            receive,
            send,
        )
