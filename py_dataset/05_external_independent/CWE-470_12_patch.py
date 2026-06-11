import importlib

# Define a whitelist of allowed modules and their allowed resolvers.
# This map should contain only the modules and functions that are explicitly
# designed to be callable via this extension mechanism.
# Any module or resolver not in this map will be rejected for security reasons.
_ALLOWED_EXTENSION_MAP = {
    "my_application.extensions.plugin_a": ["execute_task_a", "query_status_a"],
    "my_application.extensions.plugin_b": ["process_input_b", "generate_output_b"],
    # Add other safe extension modules and their specific safe functions here.
    # Example: If `some_module.safe_function` is allowed, add:
    # "some_module": ["safe_function"],
    # It is crucial to be very specific about what is allowed here.
}


def resolve_run_extension(
    _root,
    _info,
    module_name: str,
    resolver_name: str,
) -> dict:
    # CWE-470 Mitigation: Validate the module_name against the explicitly allowed list.
    # This prevents an attacker from importing arbitrary modules (e.g., 'os', 'subprocess').
    if module_name not in _ALLOWED_EXTENSION_MAP:
        raise PermissionError(f"Module '{module_name}' is not an allowed extension.")

    # CWE-470 Mitigation: Validate the resolver_name against the allowed resolvers
    # for that specific whitelisted module. This prevents an attacker from calling
    # arbitrary functions (e.g., 'system', 'eval') within an otherwise allowed module.
    allowed_resolvers = _ALLOWED_EXTENSION_MAP[module_name]
    if resolver_name not in allowed_resolvers:
        raise PermissionError(f"Resolver '{resolver_name}' is not allowed for module '{module_name}'.")

    # If both module and resolver are whitelisted, proceed with dynamic loading.
    module = importlib.import_module(
        module_name
    )
    resolver = getattr(
        module,
        resolver_name,
    )

    return {
        "result": resolver(),
    }
