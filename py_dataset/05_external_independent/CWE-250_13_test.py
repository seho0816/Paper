from celery import shared_task


@shared_task
def generate_preview(image_path: str) -> str:
    executor = privileged_task_executor()
    return executor.create_preview(image_path)
