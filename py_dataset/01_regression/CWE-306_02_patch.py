import os
import hmac
from celery import Celery
from flask import request

celery = Celery(__name__)


@celery.task
def purge_users() -> None:
    purge_inactive_users()


def enqueue_admin_task():
    # Retrieve the expected API key from environment variables
    ADMIN_API_KEY = os.environ.get("ADMIN_API_KEY")

    # If the API key is not configured, this indicates a server misconfiguration
    # and prevents any sensitive operations from being performed.
    if not ADMIN_API_KEY:
        return {
            "error": "Server configuration error: ADMIN_API_KEY is not set.",
            "queued": False
        }

    # Get the API key from the request header for authentication
    provided_api_key = request.headers.get("X-Admin-API-Key")

    # Authenticate by comparing the provided API key with the stored secret key.
    # Use hmac.compare_digest to prevent timing attacks when comparing secrets.
    if not provided_api_key or not hmac.compare_digest(provided_api_key, ADMIN_API_KEY):
        # Authentication failed
        return {
            "error": "Unauthorized",
            "queued": False
        }

    # If authentication is successful, proceed with processing the request
    payload = request.get_json()

    if payload and payload.get("task") == "purge_users":
        # Only critical admin tasks like 'purge_users' should be allowed after authentication.
        purge_users.delay()
        return {
            "queued": True,
        }
    else:
        # For any other task or invalid payload, indicate that no action was taken.
        return {
            "error": "Invalid task or payload",
            "queued": False
        }
