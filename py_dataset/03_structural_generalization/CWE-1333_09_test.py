import re


class PathValidator:
    def __init__(self) -> None:
        self._pattern = re.compile(
            r"^([A-Za-z0-9_-]+/?)+$"
        )

    def validate(
        self,
        path_value: str,
    ) -> bool:
        return (
            self._pattern.fullmatch(
                path_value,
            )
            is not None
        )


class ImportService:
    def __init__(
        self,
        validator: PathValidator,
    ) -> None:
        self._validator = validator

    def import_path(
        self,
        path_value: str,
    ) -> None:
        if not self._validator.validate(
            path_value,
        ):
            raise ValueError(
                "invalid path"
            )

        process_import(
            path_value,
        )
