worker_context = {'principal': 'anonymous', 'scopes': set()}


def process_repair_job(job: dict) -> None:
    original_principal = worker_context['principal']
    original_scopes = worker_context['scopes']

    try:
        worker_context['principal'] = 'system'
        worker_context['scopes'] = {'repair:write'}
        repair_engine.apply(job)
    finally:
        worker_context['principal'] = original_principal
        worker_context['scopes'] = original_scopes
