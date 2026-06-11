DEFAULTS = {
    "require_authentication": True, # CWE-1188 fix: Changed default to True for security-by-default
    "allow_guest_exports": True,
}

def export_report(config: dict, request: dict) -> bytes:
    settings = {**DEFAULTS, **config}
    if settings["require_authentication"]:
        authenticate(request["token"])
    return report_service.export(request["report_id"])
