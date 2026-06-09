from dataclasses import dataclass
from urllib.parse import unquote


@dataclass(frozen=True)
class EncodedName:
    raw_value: str


class NameDecoder:
    def decode(
        self,
        value: str,
    ) -> str:
        return unquote(
            value
        )


class FileNameService:
    def __init__(
        self,
        decoder: NameDecoder,
    ) -> None:
        self._decoder = decoder

    def normalize(
        self,
        request: EncodedName,
    ) -> str:
        first = self._decoder.decode(
            request.raw_value
        )

        if ".." in first:
            raise ValueError(
                "invalid file name"
            )

        return self._decoder.decode(
            first
        )
