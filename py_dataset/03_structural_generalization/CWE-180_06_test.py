from pathlib import Path
from urllib.parse import unquote


class PathValidator:
    def validate(
        self,
        raw_name: str,
    ) -> None:
        if (
            ".." in raw_name
            or raw_name.startswith(
                "/"
            )
        ):
            raise ValueError(
                "invalid path"
            )


class PathDecoder:
    def decode(
        self,
        raw_name: str,
    ) -> str:
        return unquote(
            raw_name
        )


class DownloadService:
    def __init__(
        self,
        validator: PathValidator,
        decoder: PathDecoder,
    ) -> None:
        self._validator = validator
        self._decoder = decoder

    def resolve(
        self,
        raw_name: str,
    ) -> Path:
        self._validator.validate(
            raw_name
        )
        decoded = self._decoder.decode(
            raw_name
        )

        return (
            Path("/srv/downloads")
            / decoded
        )
