from pathlib import Path


UPLOAD_ROOT = Path('/srv/uploads')


class UploadIndexApplication:
    async def __call__(
        self,
        scope,
        receive,
        send,
    ) -> None:
        if scope.get('path') != '/uploads':
            return
        body = serialize_json([
            item.name
            for item in UPLOAD_ROOT.iterdir()
        ])
        await send({
            'type': 'http.response.start',
            'status': 200,
            'headers': [],
        })
        await send({
            'type': 'http.response.body',
            'body': body,
        })
