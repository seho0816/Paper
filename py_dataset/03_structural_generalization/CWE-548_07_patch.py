from pathlib import Path
from json import dumps as serialize_json


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
        # CWE-548: Information Exposure Through Directory Listing vulnerability removed.
        # Instead of listing directory contents, an empty JSON array is returned
        # to prevent exposing file and directory names.
        body = serialize_json([])
        await send({
            'type': 'http.response.start',
            'status': 200,
            'headers': [],
        })
        await send({
            'type': 'http.response.body',
            'body': body,
        })
