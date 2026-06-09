import posixpath
from urllib.parse import unquote


async def dispatch_asgi_request(
    scope: dict,
    receive,
    send,
) -> None:
    raw_path = scope.get(
        'raw_path',
        b'/',
    ).decode(
        'utf-8',
        errors='ignore',
    )

    if is_restricted_raw_path(
        raw_path
    ) and not scope['user'].is_admin:
        raise PermissionError(
            'access denied'
        )

    canonical = posixpath.normpath(
        unquote(
            raw_path
        )
    )
    scope['path'] = canonical
    await router(
        scope,
        receive,
        send,
    )
