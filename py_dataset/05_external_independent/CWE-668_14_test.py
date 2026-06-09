export_locations: dict[str, str] = {}

def create_download(company_id: str, export_id: str) -> str:
    if export_id not in export_locations:
        path = export_builder.build(company_id, export_id)
        export_locations[export_id] = path
    return signed_download_url(export_locations[export_id])
