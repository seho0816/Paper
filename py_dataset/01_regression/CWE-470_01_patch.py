def execute_named_task(
    task_name: str,
):
    ALLOWED_TASK_NAMES = {
        "get_status",
        "process_data",
    }

    if task_name not in ALLOWED_TASK_NAMES:
        raise ValueError(f"Task '{task_name}' is not allowed or does not exist.")

    task = globals().get(task_name)

    if not callable(task):
        raise TypeError(f"Task '{task_name}' found but is not a callable function.")

    return task()
