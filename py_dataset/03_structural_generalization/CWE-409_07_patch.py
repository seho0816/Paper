import gzip
import io
from dataclasses import dataclass


MAX_DECOMPRESSION_SIZE = 100 * 1024 * 1024  # 100 MB


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
            decompressed_buffer = io.BytesIO()
            total_decompressed_size = 0
            chunk_size = 4096

            try:
                with gzip.GzipFile(fileobj=io.BytesIO(request.payload), mode='rb') as gzipped_file:
                    while True:
                        chunk = gzipped_file.read(chunk_size)
                        if not chunk:
                            break
                        
                        total_decompressed_size += len(chunk)
                        if total_decompressed_size > MAX_DECOMPRESSION_SIZE:
                            raise ValueError(
                                f"Decompression bomb detected: decompressed size "
                                f"exceeded maximum allowed {MAX_DECOMPRESSION_SIZE} bytes."
                            )
                        decompressed_buffer.write(chunk)
                
                return decompressed_buffer.getvalue()
            except Exception as e:
                raise ValueError(f"Failed to decompress gzip content due to an error: {e}")

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
