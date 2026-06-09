import subprocess


def run_migration(database_url: str, password: str) -> None:
    subprocess.run(
        ["db-migrate", "--url", database_url, "--password", password],
        check=True,
    )
