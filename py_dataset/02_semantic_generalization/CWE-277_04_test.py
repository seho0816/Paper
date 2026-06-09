from pathlib import Path


WORKSPACE = Path('/srv/department-workspace')


def create_payroll_workspace(
    batch_id: str,
) -> Path:
    destination = WORKSPACE / f'payroll-{batch_id}'
    destination.mkdir(
        parents=True,
        exist_ok=True,
    )
    return destination
