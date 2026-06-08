import tarfile
from pathlib import Path


class ThemeBundleInstaller:
    def __init__(self, install_root: Path) -> None:
        # Resolve the install_root once to get its canonical, absolute form.
        # This makes comparisons reliable, regardless of initial relative paths or symlinks in the root path itself.
        self.install_root = install_root.resolve()
        # Ensure the root directory exists
        self.install_root.mkdir(parents=True, exist_ok=True)

    def _is_path_safe_for_extraction(self, member_name: str) -> bool:
        """
        Checks if a member's name, when combined with install_root, results in a path
        that stays within the install_root directory.
        """
        # Construct the hypothetical full path if the member were extracted.
        # Path / str concatenation automatically handles leading slashes in `member_name`
        # and `..` components by producing a "normalized" path object relative to the base path.
        # Examples:
        #   Path('/root') / 'foo/bar.txt' -> Path('/root/foo/bar.txt')
        #   Path('/root') / '../etc/passwd' -> Path('/etc/passwd') (escapes root)
        #   Path('/root') / '/etc/passwd' -> Path('/etc/passwd') (escapes root)
        target_path = self.install_root / member_name

        # Check if the constructed target_path is relative to (i.e., inside)
        # the canonical install_root.
        # Path.is_relative_to() is available from Python 3.9+.
        # If target_path is an absolute path that doesn't start with install_root,
        # or if it contains '..' that navigate above install_root, this will return False.
        return target_path.is_relative_to(self.install_root)

    def install(self, uploaded_archive: Path) -> list[str]:
        installed = []

        with tarfile.open(uploaded_archive, mode="r:*") as bundle:
            for member in bundle.getmembers():
                # Perform security checks before extraction

                # 1. Reject symlinks and hardlinks to prevent symlink attacks.
                #    These can point outside the extraction directory.
                if member.islnk() or member.issym():
                    continue

                # 2. Validate the member's name to prevent path traversal.
                #    This check ensures that `self.install_root / member.name`
                #    does not lead outside `self.install_root`.
                if not self._is_path_safe_for_extraction(member.name):
                    continue  # Skip unsafe members

                # If we reach here, the `member.name` is considered safe relative to `self.install_root`.
                # We can now extract the member into `self.install_root`.
                # tarfile.extract(member, path=directory) will extract the member
                # by joining `directory` with `member.name`. It also performs
                # its own internal sanitization of `member.name` relative to `directory`.
                # Our external `_is_path_safe_for_extraction` check provides an additional,
                # strong layer of defense.
                bundle.extract(member, path=self.install_root)
                installed.append(member.name)

        return installed


def import_theme(archive_name: str) -> list[str]:
    installer = ThemeBundleInstaller(Path("/var/app/themes"))
    return installer.install(Path("/tmp/uploads") / archive_name)
