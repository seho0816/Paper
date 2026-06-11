from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class BackupArtifact:
    name: str
    content: bytes


class PublicBackupRepository:
    def __init__(self) -> None:
        self._root = Path("static") / "backups"

    def save(self, artifact: BackupArtifact) -> Path:
        self._root.mkdir(parents=True, exist_ok=True)
        
        # Sanitize the artifact name to prevent directory traversal vulnerabilities (CWE-22)
        # which can lead to files being accessible to external parties (CWE-552).
        # Path(artifact.name).name extracts only the final path component,
        # neutralizing '..', '/', '\', and absolute paths.
        # E.g., "foo/bar.txt" becomes "bar.txt", "../secret.txt" becomes "secret.txt",
        # and "/etc/passwd" becomes "passwd".
        safe_filename = Path(artifact.name).name
        
        # Ensure the filename is not empty after sanitization (e.g., if artifact.name was "foo/").
        if not safe_filename:
            raise ValueError("Invalid artifact name: Filename cannot be empty or solely a directory path.")
            
        # Construct the full target path within the intended root directory.
        target = self._root / safe_filename
        
        # Robust validation: Resolve both the root and the target paths to their absolute, normalized forms.
        # This catches any remaining path traversal attempts, including tricky ones involving symbolic links
        # or special directory names like '.' or '..' that Path.name might not fully neutralize in all contexts.
        resolved_root = self._root.resolve()
        resolved_target = target.resolve()
        
        # Ensure the resolved target path is strictly within or is the resolved root path itself.
        # This prevents any files from being written outside the designated backup directory,
        # and also prevents writing to the root directory itself with names like '.' or '..'.
        if not resolved_target.is_relative_to(resolved_root):
            raise ValueError("Invalid artifact name: Path traversal detected. File must be saved within the designated backup directory.")
        
        # The parent directory of 'target' is guaranteed to be 'self._root' since 'safe_filename'
        # is a simple filename. 'self._root' is already created by self._root.mkdir().
        # Therefore, no additional directory creation is needed for 'target.parent'.

        target.write_bytes(artifact.content)
        return target
