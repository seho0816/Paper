from pathlib import Path
import shutil


def resolve_publish_document(
    _root,
    info,
    staged_path: str,
) -> dict:
    source = Path(staged_path)
    target = (
        info.context.document_root
        / source.name
    )
    shutil.copy2(
        source,
        target,
    )
    return {
        'path': str(target),
    }
