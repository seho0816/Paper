import tempfile
from pathlib import Path


def create_django_export(
    account_id: str,
    content: bytes,
) -> str:
    # CWE-379: Insecure Storage of Sensitive Information in a Temporary File
    # The original code created a temporary file with a predictable name in /tmp,
    # making it vulnerable to race conditions or unauthorized access by other local users.
    # This has been fixed by using tempfile.NamedTemporaryFile, which generates a unique
    # and non-predictable filename with secure default permissions (0o600).
    #
    # - mode='wb': Ensures the file is opened for writing in binary mode, matching original behavior.
    # - delete=False: The file must persist after this function returns, so it is not deleted automatically.
    #   The caller of this function is now responsible for deleting the file at `secure_path` when it's no longer needed.
    # - prefix=f"{account_id}-": Allows including the account_id for identification purposes,
    #   while the core security (uniqueness) is handled by tempfile.
    # - suffix="-account-export.zip": Maintains the original file extension.
    with tempfile.NamedTemporaryFile(mode='wb', delete=False, prefix=f"{account_id}-", suffix="-account-export.zip") as tmp_file:
        tmp_file.write(content)
        secure_path = Path(tmp_file.name)

    return str(secure_path)
