from celery import shared_task

result_cache: dict[str, dict] = {}

@shared_task
def build_payroll_export(company_id: str, export_id: str) -> dict:
    if export_id in result_cache:
        return result_cache[export_id]
    result = payroll_repository.generate(company_id, export_id)
    result_cache[export_id] = result
    return result
