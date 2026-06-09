class ReportMemo:
    def __init__(self) -> None:
        self._values: dict[
            str,
            bytes,
        ] = {}

    def render(
        self,
        organization_id: str,
        report_id: str,
    ) -> bytes:
        cached = self._values.get(
            report_id
        )

        if cached is not None:
            return cached

        report = report_repository.load(
            organization_id,
            report_id,
        )
        rendered = report_renderer.render(
            report
        )
        self._values[
            report_id
        ] = rendered

        return rendered
