import re
from pathlib import Path


# NOTE: serialize_account function is not provided in the original code,
# but it's part of the original code's signature, so it must be assumed to exist
# or be imported from somewhere if this were a full application.
# For this exercise, we will assume it is globally available or defined elsewhere
# as per the strict rules of maintaining the overall structure and not adding/removing functionality.
# Example placeholder if it were needed for execution outside this context:
# def serialize_account(account: dict) -> str:
#     import json
#     return json.dumps(account)


class DiagnosticExportService:
    def __init__(self) -> None:
        self._directory = Path("media") / "diagnostics"

    def create(self, account: dict) -> str:
        self._directory.mkdir(parents=True, exist_ok=True)
        # CWE-552: Files or Directories Accessible to External Parties
        # The 'account['id']' is used directly in the filename. If this input
        # contains path traversal sequences (e.g., "../") or other problematic
        # characters, an attacker could manipulate the filename to access or
        # create files outside the intended directory. This can lead to unintended
        # information disclosure or other security issues.
        # To mitigate this, sanitize the account ID to ensure it contains
        # only safe characters suitable for a filename component, preventing
        # path traversal and problematic characters.
        safe_account_id = re.sub(r'[^a-zA-Z0-9_-]', '', str(account['id']))

        target = self._directory / f"account-{safe_account_id}.json"
        target.write_text(serialize_account(account), encoding="utf-8")
        return "/media/diagnostics/" + target.name
