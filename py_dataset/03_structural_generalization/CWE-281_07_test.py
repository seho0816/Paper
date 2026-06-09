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
        shutil.copyfile(
            source,
            destination,
        )
        shutil.copystat(
            source,
            destination,
        )
        return destination
