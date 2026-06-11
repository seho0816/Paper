from dataclasses import dataclass
from collections import OrderedDict


@dataclass(frozen=True)
class PreviewRequest:
    template_id: str
    locale: str


class PreviewCache:
    # CWE-770: Allocation of Resources Without Limits or Throttling
    # The cache currently has no size limit, allowing it to grow indefinitely and potentially
    # exhaust system memory, leading to a denial of service.
    # To fix this, a maximum cache size is introduced, and an LRU (Least Recently Used)
    # eviction policy is implemented using collections.OrderedDict.
    # The MAX_CACHE_SIZE is set as a class constant to maintain the __init__ method's signature.
    MAX_CACHE_SIZE = 1000  # Define a reasonable maximum number of entries for the cache.

    def __init__(self) -> None:
        # Changed _entries to OrderedDict to support LRU eviction.
        self._entries: OrderedDict[str, bytes] = OrderedDict()

    def put(
        self,
        key: str,
        value: bytes,
    ) -> None:
        # Add or update the key-value pair.
        # In OrderedDict, assigning to an existing key moves it to the end (most recently used).
        # For a new key, it's added to the end.
        self._entries[key] = value

        # If the cache size exceeds the maximum allowed, remove the least recently used item.
        # popitem(last=False) removes the first (oldest/LRU) item.
        if len(self._entries) > self.MAX_CACHE_SIZE:
            self._entries.popitem(last=False)


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
        # render_preview is assumed to be an external function or method available in scope.
        # Its implementation is not part of the vulnerability being addressed here.
        preview = render_preview(request)
        self._cache.put(cache_key, preview)

        return preview
