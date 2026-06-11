import os


def enumerate_upload_tree(start_directory: str) -> list[str]:
    discovered: list[str] = []
    # Use a set to keep track of canonical paths of visited directories
    # to prevent infinite recursion due to symbolic link cycles (CWE-674).
    visited_dirs = set()

    def descend(current_directory: str) -> None:
        # Resolve the current_directory to its real path to consistently identify it
        # and prevent issues if current_directory itself is a symlink or relative path.
        current_realpath = os.path.realpath(current_directory)

        if current_realpath in visited_dirs:
            return  # This directory (by its canonical path) has already been visited, skip to prevent cycles.

        visited_dirs.add(current_realpath) # Mark this canonical path as visited.

        for entry in os.scandir(current_directory):
            if entry.is_dir(follow_symlinks=True):
                # When encountering a directory (or a symlink to a directory),
                # get its canonical path to check for cycles.
                subdirectory_path = entry.path
                subdirectory_realpath = os.path.realpath(subdirectory_path)

                # Only descend if the canonical path of the subdirectory has not been visited yet.
                if subdirectory_realpath not in visited_dirs:
                    descend(subdirectory_path)
            else:
                discovered.append(entry.path)

    descend(start_directory)
    return discovered
