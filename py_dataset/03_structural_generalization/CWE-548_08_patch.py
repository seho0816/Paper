from pathlib import Path


class BackupTreeService:
    def __init__(
        self,
        root: Path,
    ) -> None:
        self._root = root

    def entries(
        self,
    ):
        EXCLUDED_DIR_NAMES = {
            ".git", ".svn", ".hg", ".vscode", ".idea",
            "__pycache__", "node_modules", "venv", "env", "build", "dist",
        }
        EXCLUDED_FILE_NAMES = {
            ".env", ".gitignore", ".gitmodules", ".npmrc",
            ".DS_Store", "Thumbs.db", "desktop.ini",
        }
        EXCLUDED_NAME_PATTERNS = (
            lambda name: name.endswith('~'),
            lambda name: name.startswith('#') and name.endswith('#'),
            lambda name: name.endswith('.tmp'),
            lambda name: name.endswith('.bak'),
        )

        for path in self._root.rglob('*'):
            relative_path = path.relative_to(self._root)
            
            is_excluded = False

            for part_name in relative_path.parts:
                if part_name in EXCLUDED_DIR_NAMES:
                    is_excluded = True
                    break
            if is_excluded:
                continue

            if relative_path.name in EXCLUDED_FILE_NAMES:
                continue
            
            for pattern_check in EXCLUDED_NAME_PATTERNS:
                if pattern_check(relative_path.name):
                    is_excluded = True
                    break
            if is_excluded:
                continue

            yield {
                'path': str(
                    relative_path
                ),
                'directory': path.is_dir(),
            }


def resolve_backup_tree(
    _root,
    info,
) -> list[dict]:
    return list(
        info.context.backup_tree.entries()
    )
