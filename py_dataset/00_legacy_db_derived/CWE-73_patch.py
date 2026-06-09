from pathlib import Path


class ReportExportService:
    # A base directory for all exports. This should be configured securely.
    # We use a subdirectory named "exports" relative to the current working directory.
    # .resolve() makes it an absolute path and normalizes it, which is good practice.
    _BASE_EXPORT_DIR = Path("./exports").resolve()

    def __init__(self):
        # Ensure the base directory exists.
        # parents=True creates any necessary parent directories.
        # exist_ok=True prevents an error if the directory already exists.
        self._BASE_EXPORT_DIR.mkdir(parents=True, exist_ok=True)

    def export_rows(self, requested_path: str, rows: list[str]) -> Path:
        # Extract only the filename component from the requested_path.
        # This is crucial for CWE-73 fix as it prevents directory traversal attempts.
        # For example:
        # - if requested_path is "../../../etc/passwd", Path(requested_path).name will be "passwd".
        # - if requested_path is "my/report.csv", Path(requested_path).name will be "report.csv".
        safe_filename = Path(requested_path).name

        # Additionally, handle cases where the user might provide problematic filenames
        # such as ".", "..", or an empty string. These could lead to attempts to write
        # outside the intended directory or directly to the directory itself.
        if not safe_filename or safe_filename in (".", ".."):
            # Provide a safe and generic default filename if the requested one is problematic.
            # This ensures that a valid file is always created within the designated export directory,
            # preventing path traversal or attempts to write to directories.
            safe_filename = "report_export.csv"

        # Construct the full output path by joining the secure base directory
        # with the sanitized filename. This guarantees the file is created
        # strictly within the intended export directory, addressing CWE-73.
        output_path = self._BASE_EXPORT_DIR / safe_filename

        output_path.write_text("\n".join(rows), encoding="utf-8")
        return output_path


def export_monthly_report(path_from_request: str) -> Path:
    service = ReportExportService()
    return service.export_rows(path_from_request, ["date,total", "2026-06-01,30000"])
