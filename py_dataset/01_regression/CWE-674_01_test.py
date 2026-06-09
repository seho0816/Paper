import os


def enumerate_upload_tree(start_directory: str) -> list[str]:
    discovered: list[str] = []

    def descend(current_directory: str) -> None:
        for entry in os.scandir(current_directory):
            if entry.is_dir(follow_symlinks=True):
                descend(entry.path)
            else:
                discovered.append(entry.path)

    descend(start_directory)
    return discovered
