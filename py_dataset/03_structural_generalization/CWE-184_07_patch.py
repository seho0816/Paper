from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ImportEntry:
    entry_name: str
    content: bytes


class EntryNameFilter:
    def clean(
        self,
        name: str,
    ) -> str:
        # CWE-184: Incomplete Blacklist for Path Traversal.
        # The original `name.replace("../", "")` is insufficient and can be bypassed
        # (e.g., with `....//`, `subdir/../../`, or by providing absolute paths).
        # This fix aims to robustly sanitize the name to prevent directory traversal
        # by ensuring the resulting path is always relative and does not escape
        # the intended root directory.

        cleaned_path = Path(name)

        # Step 1: Handle absolute paths. If the path is absolute (e.g., /etc/passwd or C:\foo),
        # strip its root component to make it relative.
        # The goal is that the cleaned_name should be a relative path that can be safely
        # joined with self._root.
        if cleaned_path.is_absolute():
            # Example: Path('/a/b').parts -> ('/', 'a', 'b')
            # We want to process parts from 'a' onwards.
            parts_to_process = cleaned_path.parts[1:] if cleaned_path.parts else []
        else:
            parts_to_process = cleaned_path.parts

        # Step 2: Iterate through path components, building a safe relative path.
        # This logic filters out '.' (current directory) and '..' (parent directory)
        # components to prevent traversal above the conceptual starting point.
        safe_parts = []
        depth = 0  # Represents the current logical depth within the conceptual root.

        for part in parts_to_process:
            if part == "" or part == ".":
                # Ignore empty parts and current directory references.
                continue
            elif part == "..":
                # If '..' would move up from the conceptual root (depth <= 0),
                # we filter it out to prevent directory traversal.
                # Otherwise, pop the previous directory and decrease depth.
                if depth > 0:
                    depth -= 1
                    safe_parts.pop()
                else:
                    # Attempt to go above the conceptual root. Filter this '..'.
                    pass
            else:
                # Add valid directory/file names and increase depth.
                safe_parts.append(part)
                depth += 1
        
        # If no safe parts remain after filtering (e.g., input was '../../..' or '/'),
        # return '.', which represents the current directory.
        # This results in `self._root / '.'`, which is `self._root`.
        # Attempting to write a file to a directory (self._root) will typically fail
        # with an IsADirectoryError, thus preventing accidental overwrites of _root.
        if not safe_parts:
            return "."  # Path('.').as_posix() == '.'
        
        # Reconstruct the path from the safe parts. Use as_posix() for consistency
        # regardless of the underlying operating system.
        return Path(*safe_parts).as_posix()


class ArchiveImporter:
    def __init__(
        self,
        root: Path,
        name_filter: EntryNameFilter,
    ) -> None:
        self._root = root
        self._name_filter = name_filter

    def store(
        self,
        entry: ImportEntry,
    ) -> Path:
        target = (
            self._root
            / self._name_filter.clean(
                entry.entry_name
            )
        )
        target.write_bytes(
            entry.content
        )

        return target
