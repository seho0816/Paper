class ReportMemo:
    def __init__(self) -> None:
        self._values: dict[
            tuple[str, str],  # Changed key type to tuple
            bytes,
        ] = {}

    def render(
        self,
        organization_id: str,
        report_id: str,
    ) -> bytes:
        # CWE-668 Fix: Use a composite key including organization_id
        # to prevent reports from one organization being exposed to another.
        cache_key = (organization_id, report_id)
        cached = self._values.get(
            cache_key
        )

        if cached is not None:
            return cached

        # report_repository and report_renderer are assumed to be defined elsewhere
        report = report_repository.load(
            organization_id,
            report_id,
        )
        rendered = report_renderer.render(
            report
        )
        self._values[
            cache_key  # Use the composite key for storage
        ] = rendered

        return rendered
