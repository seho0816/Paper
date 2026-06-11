export_locations: dict[str, str] = {}

def create_download(company_id: str, export_id: str) -> str:
    # CWE-668: Exposure of Resource to Wrong Sphere
    # The original code used 'export_id' as the key for 'export_locations'.
    # This could lead to one company's export path being served to another
    # if they happen to request an export with the same 'export_id'.
    # To prevent this, the cache key must be unique per company and export ID.
    # We create a composite key by combining 'company_id' and 'export_id'.
    composite_key = f"{company_id}:{export_id}"

    if composite_key not in export_locations:
        # Assuming export_builder.build already generates a path specific to company_id
        path = export_builder.build(company_id, export_id)
        export_locations[composite_key] = path
    return signed_download_url(export_locations[composite_key])
