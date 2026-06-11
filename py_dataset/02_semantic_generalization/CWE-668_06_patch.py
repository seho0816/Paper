from celery import shared_task

result_cache: dict[tuple[str, str], dict] = {}

@shared_task
def build_payroll_export(company_id: str, export_id: str) -> dict:
    cache_key = (company_id, export_id)
    if cache_key in result_cache:
        return result_cache[cache_key]
    result = payroll_repository.generate(company_id, export_id)
    result_cache[cache_key] = result
    return result
