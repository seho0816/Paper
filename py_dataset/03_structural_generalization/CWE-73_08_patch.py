from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ReportRequest:
    destination: Path
    report_id: str


class ReportWriter:
    def write(
        self,
        request: ReportRequest,
    ) -> Path:
        # Define a secure base directory for reports.
        # In a production environment, this path should be configurable
        # (e.g., via environment variable) and ideally an absolute path
        # to prevent unexpected behavior if the script's CWD changes.
        # For this exercise, using Path.cwd() / "reports" provides a
        # consistent and isolated location.
        secure_base_dir = Path.cwd() / "reports"
        secure_base_dir.mkdir(parents=True, exist_ok=True)

        # CWE-73 fix: Prevent path traversal and arbitrary file overwrites.
        # Extract only the name component from the user-provided destination path.
        # This effectively nullifies any attempts to use absolute paths (e.g., /etc/passwd)
        # or path traversal sequences (e.g., ../../../) by only taking the final filename.
        file_name = request.destination.name

        # Handle edge case where request.destination.name might be empty (e.g., if Path('.') or Path('/') was provided).
        # An empty filename would cause write_bytes to attempt writing to the directory itself, resulting in IsADirectoryError.
        # To prevent this operational error without introducing new vulnerabilities or dummy values,
        # a safe filename derived from report_id is used as a fallback.
        if not file_name:
            file_name = f"report_{request.report_id}.txt"

        # Construct the final, safe path by joining the secure base directory with the sanitized filename.
        final_safe_path = secure_base_dir / file_name

        content = render_report(
            request.report_id
        )
        final_safe_path.write_bytes(
            content
        )

        return final_safe_path

# Assume render_report is defined elsewhere and accessible.
# Its definition is not provided in the vulnerable code snippet, so it's not included here.
