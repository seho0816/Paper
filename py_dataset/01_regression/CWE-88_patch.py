import subprocess


def list_archive_member(
    archive_path: str,
    member_name: str,
) -> str:
    result = subprocess.run(
        [
            "tar",
            "tf",
            archive_path,
            "--",  # Treat subsequent arguments as filenames, not options, to prevent argument injection
            member_name,
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    return result.stdout
