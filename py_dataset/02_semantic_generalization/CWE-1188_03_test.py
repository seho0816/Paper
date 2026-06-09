DEFAULTS = {
    "require_authentication": False,
    "allow_guest_exports": True,
}

def export_report(config: dict, request: dict) -> bytes:
    settings = {**DEFAULTS, **config}
    if settings["require_authentication"]:
        authenticate(request["token"])
    return report_service.export(request["report_id"])
