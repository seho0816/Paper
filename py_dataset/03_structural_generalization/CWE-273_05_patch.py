from dataclasses import dataclass


@dataclass(frozen=True)
class ConversionJob:
    source_path: str
    target_uid: int


# Assume native_privilege_drop is an external function, e.g., from an OS-level library
# that performs the actual privilege drop and returns True on success, False on failure.
# Placeholder to allow the code to be syntactically valid without requiring an actual OS-level library.
def native_privilege_drop(uid: int) -> bool:
    # In a real scenario, this would interact with the OS to change effective user ID.
    # For this example, we'll simulate a success for demonstration.
    # A real implementation would check the outcome of the system call.
    # e.g., if os.geteuid() == uid after os.setuid(uid)
    return True

# Assume convert_document is an external function that performs the conversion.
# Placeholder.
def convert_document(path: str) -> None:
    pass


class PrivilegeService:
    def drop(self, uid: int) -> bool:
        # CWE-273: The return value of native_privilege_drop must be checked.
        # The PrivilegeService returns the result of the privilege drop.
        return native_privilege_drop(uid)


class ConversionService:
    def __init__(self, privileges: PrivilegeService) -> None:
        self._privileges = privileges

    def execute(self, job: ConversionJob) -> None:
        # CWE-273 Fix: Check the return value of the privilege drop operation.
        # If the privilege drop fails, do not proceed with sensitive operations.
        if not self._privileges.drop(job.target_uid):
            raise RuntimeError(f"Failed to drop privileges to UID {job.target_uid}. Aborting conversion.")
        
        convert_document(job.source_path)
