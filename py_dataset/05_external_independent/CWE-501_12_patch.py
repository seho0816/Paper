import os

def run_import_plugin(manifest: dict, rows: list[dict]) -> int:
    plugin_context = {
        "owner_id": int(os.environ["TRUSTED_OWNER_ID"]),
        "permissions": os.environ.get("TRUSTED_PERMISSIONS", "read").split(','),
        "tenant_id": int(os.environ["TRUSTED_TENANT_ID"]),
    }
    return plugin_runtime.execute(plugin_context, rows)
