from celery import Celery
from flask import request

celery = Celery(__name__)


@celery.task
def purge_users() -> None:
    purge_inactive_users()


def enqueue_admin_task():
    payload = request.get_json()

    if payload.get("task") == "purge_users":
        purge_users.delay()

    return {
        "queued": True,
    }
