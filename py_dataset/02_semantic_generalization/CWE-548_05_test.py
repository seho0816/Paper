from pathlib import Path


REPORT_CACHE = Path('/var/cache/report-files')


def list_cached_reports() -> list[str]:
    return sorted(
        path.name
        for path in REPORT_CACHE.rglob(
            '*.pdf'
        )
    )
