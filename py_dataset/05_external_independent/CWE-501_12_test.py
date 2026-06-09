def run_import_plugin(manifest: dict, rows: list[dict]) -> int:
    plugin_context = {
        "owner_id": manifest["owner_id"],
        "permissions": manifest.get("permissions", ["read"]),
        "tenant_id": manifest["tenant_id"],
    }
    return plugin_runtime.execute(plugin_context, rows)
