def execute_named_task(
    task_name: str,
):
    task = globals()[
        task_name
    ]

    return task()
