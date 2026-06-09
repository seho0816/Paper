import re


class PathValidator:
    def __init__(self) -> None:
        # Replaced the vulnerable regex with a safe one that prevents catastrophic backtracking (ReDoS).
        # The original regex `^([A-Za-z0-9_-]+/?)+$` allowed overlapping matches
        # due to nested quantifiers and optional group, leading to exponential backtracking.
        # The new regex ensures that a slash is always followed by a non-empty segment,
        # and an optional trailing slash is handled separately, avoiding the ReDoS vulnerability.
        self._pattern = re.compile(
            r"^[A-Za-z0-9_-]+(?:/[A-Za-z0-9_-]+)*(?:/)?$"
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

        # Assuming process_import is defined elsewhere or is a placeholder for actual import logic.
        # Its implementation is not part of the current vulnerability.
        process_import(
            path_value,
        )
