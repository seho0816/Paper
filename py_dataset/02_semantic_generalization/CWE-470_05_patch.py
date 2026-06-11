import importlib

# Whitelist of allowed backend modules for CWE-470 fix.
# These should be specific, trusted modules that your application is designed to load dynamically.
# For this example, we use illustrative names that demonstrate the whitelisting concept.
ALLOWED_BACKEND_MODULES = {
    "my_application.backends.default_implementation",
    "my_application.backends.alternative_implementation",
}

# A dictionary mapping allowed module names to a set of allowed class names within that module.
# This ensures that even from an allowed module, only specific, trusted classes can be loaded.
ALLOWED_BACKEND_CLASSES_BY_MODULE = {
    "my_application.backends.default_implementation": {
        "DefaultServiceBackend",
        "LegacyServiceBackend",
    },
    "my_application.backends.alternative_implementation": {
        "AdvancedServiceBackend",
    },
}


def load_configured_backend(
    configuration: dict,
):
    module_name = configuration["backend_module"]
    class_name = configuration["backend_class"]

    # CWE-470 fix: Validate module_name against a whitelist to prevent arbitrary module loading.
    if module_name not in ALLOWED_BACKEND_MODULES:
        raise ValueError(f"Attempted to load an untrusted backend module: {module_name}")

    backend_module = importlib.import_module(module_name)

    # CWE-470 fix: Validate class_name against a whitelist specific to the allowed module
    # to prevent loading unintended classes or methods (e.g., dunder methods, internal utilities).
    if module_name in ALLOWED_BACKEND_CLASSES_BY_MODULE:
        if class_name not in ALLOWED_BACKEND_CLASSES_BY_MODULE[module_name]:
            raise ValueError(f"Attempted to load an untrusted class '{class_name}' from module '{module_name}'")
    else:
        # If an allowed module is not explicitly listed in ALLOWED_BACKEND_CLASSES_BY_MODULE,
        # it implies no classes from it are allowed to be dynamically loaded via this mechanism.
        # This provides maximum security by requiring explicit whitelisting for all components.
        raise ValueError(f"No classes are whitelisted for dynamic loading from module: {module_name}")

    backend_class = getattr(
        backend_module,
        class_name,
    )

    return backend_class()
