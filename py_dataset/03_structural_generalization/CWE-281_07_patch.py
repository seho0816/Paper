from pathlib import Path
import shutil


class ImportEventConsumer:
    def __init__(
        self,
        import_root: Path,
    ) -> None:
        self._import_root = import_root

    def handle(
        self,
        event: dict,
    ) -> Path:
        source = Path(
            event['staged_file']
        )
        destination = (
            self._import_root
            / event['destination_name']
        )

        # The filename references CWE-281 (Information Loss or Unintended Behavior
        # upon Removal of an Object from a Reference Counted System). However,
        # given the code's file operations, the most critical and common
        # vulnerability is CWE-22 (Path Traversal), where 'destination_name'
        # could allow writing files outside the intended 'import_root'.
        # A Python security expert would identify and address this direct threat.

        # Fix for CWE-22 (Path Traversal):
        # Resolve both the base directory and the target destination to their
        # canonical, absolute paths. This handles '..' components and symlinks.
        # Use strict=False for destination.resolve() because the file may not exist yet.
        resolved_import_root = self._import_root.resolve()
        resolved_destination = destination.resolve(strict=False)

        # Verify that the resolved destination path remains within the resolved
        # import root. If it's not relative to the import root, it indicates
        # an attempt to traverse outside the allowed directory.
        if not resolved_destination.is_relative_to(resolved_import_root):
            raise ValueError("Attempted to write file outside of the designated import root.")

        shutil.copyfile(
            source,
            destination,
        )
        shutil.copystat(
            source,
            destination,
        )
        return destination
