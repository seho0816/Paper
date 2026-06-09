from pathlib import Path


ATTACHMENT_ROOT = Path('/srv/attachments')


def attachment_index() -> list[str]:
    return [
        str(path.relative_to(
            ATTACHMENT_ROOT
        ))
        for path in ATTACHMENT_ROOT.glob(
            '**/*'
        )
        if path.is_file()
    ]
