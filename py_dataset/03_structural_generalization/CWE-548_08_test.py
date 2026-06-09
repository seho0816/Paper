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
        for path in self._root.rglob('*'):
            yield {
                'path': str(
                    path.relative_to(
                        self._root
                    )
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
