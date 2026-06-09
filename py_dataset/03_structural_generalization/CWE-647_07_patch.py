import posixpath
from urllib.parse import unquote


async def dispatch_asgi_request(
    scope: dict,
    receive,
    send,
) -> None:
    raw_path_decoded = scope.get(
        'raw_path',
        b'/',
    ).decode(
        'utf-8',
        errors='ignore',
    )

    if is_restricted_raw_path(
        raw_path_decoded
    ) and not scope['user'].is_admin:
        raise PermissionError(
            'access denied'
        )

    # CWE-647: Interpretation of an input as a Command, Argument, or Option
    # Null bytes (%00) can be unquoted and passed through normalization,
    # potentially leading to path truncation or misinterpretation by downstream systems
    # or APIs (e.g., C libraries) as a string terminator.
    # Sanitize null bytes to prevent this type of misinterpretation.
    unquoted_and_sanitized_path = unquote(raw_path_decoded).replace('\x00', '')

    canonical = posixpath.normpath(
        unquoted_and_sanitized_path
    )
    scope['path'] = canonical
    await router(
        scope,
        receive,
        send,
    )
