import os
from dataclasses import dataclass
from pathlib import Path
import zipfile


@dataclass(frozen=True)
class PluginPackage:
    archive_path: Path
    plugin_id: str


class PluginInstaller:
    def __init__(self, plugin_root: Path) -> None:
        self._plugin_root = plugin_root

    def install(self, package: PluginPackage) -> Path:
        destination = (
            self._plugin_root
            / package.plugin_id
        )
        destination.mkdir(
            parents=True,
            exist_ok=True,
        )

        # Get the absolute, resolved path of the destination to validate against
        resolved_destination = destination.resolve()

        with zipfile.ZipFile(package.archive_path) as archive:
            for member in archive.infolist():
                member_path_within_zip = Path(member.filename)

                # Prevent absolute paths or paths with drive letters, which could escape to arbitrary locations
                if member_path_within_zip.is_absolute() or member_path_within_zip.anchor:
                    raise zipfile.BadZipFile(
                        f"Attempted Zip Slip or invalid path in archive (absolute path/anchor): {member.filename}"
                    )

                # Prevent directory traversal using '..' components
                if '..' in member_path_within_zip.parts:
                    raise zipfile.BadZipFile(
                        f"Attempted Zip Slip or invalid path in archive ('..' component): {member.filename}"
                    )

                # Construct the full target path inside the destination
                target_path = destination / member_path_within_zip

                # Resolve the target path to normalize any '.' components and ensure it's absolute
                resolved_target_path = target_path.resolve()

                # Crucial validation: Ensure the resolved target path is strictly inside or equal to the resolved destination.
                # Python 3.9+ provides is_relative_to.
                if hasattr(resolved_target_path, 'is_relative_to'):
                    if not resolved_target_path.is_relative_to(resolved_destination):
                        raise zipfile.BadZipFile(
                            f"Attempted Zip Slip: {member.filename} tries to extract outside {destination}"
                        )
                else: # Fallback for Python versions < 3.9 using os.path.commonpath
                    # os.path.commonpath returns the longest path prefix that is common to all pathnames.
                    # If target_path is a descendant of destination (or destination itself),
                    # then their common path should be destination.
                    common_prefix = Path(os.path.commonpath([resolved_destination, resolved_target_path]))
                    if common_prefix != resolved_destination:
                        raise zipfile.BadZipFile(
                            f"Attempted Zip Slip: {member.filename} tries to extract outside {destination}"
                        )

                if member.is_dir():
                    target_path.mkdir(parents=True, exist_ok=True)
                else:
                    # For files, ensure parent directory exists and then extract the file content
                    target_path.parent.mkdir(parents=True, exist_ok=True)
                    with archive.open(member) as source, open(target_path, "wb") as target:
                        target.write(source.read())

        return destination
