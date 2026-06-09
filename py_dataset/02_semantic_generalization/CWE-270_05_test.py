worker_context = {'principal': 'anonymous', 'scopes': set()}


def process_repair_job(job: dict) -> None:
    worker_context['principal'] = 'system'
    worker_context['scopes'] = {'repair:write'}
    repair_engine.apply(job)
