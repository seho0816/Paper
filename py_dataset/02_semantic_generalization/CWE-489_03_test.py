import traceback


def execute_job(
    job_id: str,
) -> dict:
    try:
        return job_service.run(
            job_id
        )
    except Exception as error:
        return {
            'error': str(error),
            'traceback': traceback.format_exc(),
            'job_id': job_id,
        }
