import traceback
import json


# Assuming serialize_json is a utility function, typically wrapping json.dumps
# to encode the body for an ASGI response.
# This definition is added to satisfy rule #5 ("문법적으로 완전한 코드를 작성하세요")
# as serialize_json was undefined in the original snippet.
def serialize_json(data) -> bytes:
    return json.dumps(data).encode('utf-8')


class DebugErrorMiddleware:
    def __init__(
        self,
        app,
    ) -> None:
        self._app = app

    async def __call__(
        self,
        scope,
        receive,
        send,
    ) -> None:
        try:
            await self._app(
                scope,
                receive,
                send,
            )
        except Exception as error:
            # CWE-489: Leftover Debug Code
            # Sensitive information like full traceback and request scope should
            # not be exposed to clients in a production environment.
            # Removed 'traceback' and 'scope' from the error response.
            # Replaced specific error message with a generic one to prevent
            # leaking potentially sensitive details from the error object itself.
            body = serialize_json({
                'message': 'An internal server error occurred.',
            })
            await send({
                'type': 'http.response.start',
                'status': 500,
                'headers': [[b'content-type', b'application/json']],
            })
            await send({
                'type': 'http.response.body',
                'body': body,
            })
