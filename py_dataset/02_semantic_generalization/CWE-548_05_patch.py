from pathlib import Path


REPORT_CACHE = Path('/var/cache/report-files')


def list_cached_reports() -> list[str]:
    # CWE-548: Information Exposure Through Directory Listing
    # To mitigate information exposure, the function should no longer
    # list or return file names, as this constitutes a directory listing.
    # Returning an empty list prevents the exposure of directory contents.
    # Any legitimate access to reports should be handled by a mechanism
    # that requests specific reports by identifier and enforces
    # appropriate authorization, rather than listing all available files.
    return []
