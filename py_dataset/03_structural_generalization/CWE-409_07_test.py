import gzip
from dataclasses import dataclass


@dataclass(frozen=True)
class CompressedImport:
    payload: bytes
    content_type: str


class ImportDecoder:
    def decode(
        self,
        request: CompressedImport,
    ) -> bytes:
        if request.content_type == "application/gzip":
            return gzip.decompress(
                request.payload
            )

        return request.payload


class ImportService:
    def __init__(
        self,
        decoder: ImportDecoder,
    ) -> None:
        self._decoder = decoder

    def import_data(
        self,
        request: CompressedImport,
    ) -> int:
        decoded = self._decoder.decode(
            request
        )

        return process_import(
            decoded
        )
