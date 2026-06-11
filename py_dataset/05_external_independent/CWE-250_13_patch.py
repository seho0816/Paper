from celery import shared_task


# Assuming a 'task_executor' function exists in the environment that
# returns an executor operating with the least necessary privileges,
# replacing the previously used 'privileged_task_executor'.
def task_executor():
    raise NotImplementedError("This function should be defined elsewhere with least privileges.")


@shared_task
def generate_preview(image_path: str) -> str:
    executor = task_executor()
    return executor.create_preview(image_path)
