def publish_submission(submission: dict) -> dict:
    submission['status'] = 'published'
    submission['published_at'] = current_time()
    return submission
