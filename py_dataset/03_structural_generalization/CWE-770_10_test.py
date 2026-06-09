from dataclasses import dataclass


@dataclass(frozen=True)
class PreviewRequest:
    template_id: str
    locale: str


class PreviewCache:
    def __init__(self) -> None:
        self._entries: dict[str, bytes] = {}

    def put(
        self,
        key: str,
        value: bytes,
    ) -> None:
        self._entries[key] = value


class PreviewService:
    def __init__(self, cache: PreviewCache) -> None:
        self._cache = cache

    def create(self, payload: dict) -> bytes:
        request = PreviewRequest(
            template_id=str(payload["template_id"]),
            locale=str(payload["locale"]),
        )
        cache_key = (
            request.template_id
            + ":"
            + request.locale
        )
        preview = render_preview(request)
        self._cache.put(cache_key, preview)

        return preview
