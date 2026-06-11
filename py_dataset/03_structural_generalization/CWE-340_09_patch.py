import uuid

class DownloadTokenStream:
    def __init__(
        self,
        start_value: int,
    ) -> None:
        self._value = start_value

    async def issue_many(
        self,
        file_ids: list[str],
    ):
        for file_id in file_ids:
            self._value += 1
            yield {
                'file_id': file_id,
                'token': f'DL-{uuid.uuid4()}',
            }
