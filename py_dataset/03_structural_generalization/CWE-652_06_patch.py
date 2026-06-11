import re
from dataclasses import dataclass


@dataclass(frozen=True)
class ReportQuery:
    return_expression: str


class XmlReportService:
    # A strict regex to validate XQuery return expressions for the 'return' clause.
    # This pattern allows for:
    # 1. `$record` itself.
    # 2. Path expressions relative to `$record` (e.g., `$record/field`, `$record/field/@attr`, `$record/*`).
    #    - Path segments can be XML names (alphanumeric, _, -), `*` for any element,
    #      `@` followed by an XML name for an attribute, or `@*` for any attribute.
    # 3. Common functions like `data()`, `string()`, `count()` applied to `$record` or its paths.
    _XML_NAME_CHARS = r"[a-zA-Z0-9_\-]+"
    _PATH_SEGMENT = r"(?:(?:/" + _XML_NAME_CHARS + r")|(?:\/\*)|(?:/@" + _XML_NAME_CHARS + r")|(?:\/@\*))"
    _SAFE_RETURN_EXPRESSION_PATTERN = re.compile(
        r"^(?:\$record(?:" + _PATH_SEGMENT + r")*|"  # $record or $record/path/segment pattern
        r"(?:data|string|count)\(\$record(?:" + _PATH_SEGMENT + r")*\)"  # data($record/path) etc.
        r")$"
    )

    def __init__(
        self,
        engine,
    ) -> None:
        self._engine = engine

    def create(
        self,
        request: ReportQuery,
    ) -> str:
        # Validate the return_expression to prevent XQuery injection (CWE-652).
        # This ensures that the input only contains safe XQuery path expressions or
        # simple function calls operating on the '$record' variable, preventing
        # arbitrary XQuery execution.
        if not self._SAFE_RETURN_EXPRESSION_PATTERN.fullmatch(request.return_expression):
            raise ValueError("Invalid XQuery return expression provided.")

        query = (
            "for $record in collection('reports')/record "
            "return "
            + request.return_expression
        )

        return self._engine.query(
            query
        )
