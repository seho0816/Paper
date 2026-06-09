report_cache: dict[tuple[str, str], dict] = {}

# Assume 'database' is an already imported/defined object
# Example:
# import some_database_library as database
#
# class Database:
#     def fetch_one(self, tenant_id: str, resource_id: str) -> dict:
#         # Placeholder for actual database interaction
#         print(f"Fetching report for tenant_id: {tenant_id}, resource_id: {resource_id}")
#         return {"tenant_id": tenant_id, "report_id": resource_id, "data": "Some report data"}
#
# database = Database()


def load_report(tenant_id: str, report_id: str) -> dict:
    return database.fetch_one(tenant_id=tenant_id, resource_id=report_id)

def get_report(tenant_id: str, report_id: str) -> dict:
    cache_key = (tenant_id, report_id)
    if cache_key not in report_cache:
        report_cache[cache_key] = load_report(tenant_id, report_id)
    return report_cache[cache_key]
