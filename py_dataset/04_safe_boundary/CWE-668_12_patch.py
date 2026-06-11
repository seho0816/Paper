import json

def load_private_report(workspace_id: str, report_id: str) -> dict:
    key = f"workspace:{workspace_id}:report:{report_id}"
    cached = redis_client.get(key)
    if cached is not None:
        report = json.loads(cached)
        if report["workspace_id"] != workspace_id:
            raise PermissionError("workspace mismatch")
        return report
    report = reports.get_for_workspace(workspace_id, report_id)
    redis_client.setex(key, 120, json.dumps(report))
    return report

