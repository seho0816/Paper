def run_cleanup():
    return cleanup_records()


def run_daily_report():
    return create_daily_report()


ALLOWED_TASKS = {
    "cleanup": run_cleanup,
    "daily_report": run_daily_report,
}


def run_plugin(
    task_name: str,
):
    task = ALLOWED_TASKS.get(
        task_name
    )

    if task is None:
        raise ValueError(
            "unsupported task"
        )

    return task()
