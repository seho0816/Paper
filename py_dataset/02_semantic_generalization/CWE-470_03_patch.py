import argparse
import importlib
import sys

# CWE-470 Fix: Define a whitelist of allowed modules that can be imported.
# Replace these with the actual, safe module names expected by the application.
ALLOWED_HANDLER_MODULES = [
    "app_handler_module_one",
    "app_handler_module_two",
    "utility_service_module",
]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "handler_module"
    )
    arguments = parser.parse_args()

    # Validate the handler_module against the whitelist to prevent arbitrary module imports.
    if arguments.handler_module not in ALLOWED_HANDLER_MODULES:
        print(
            f"Error: Module '{arguments.handler_module}' is not an allowed handler. "
            f"Allowed modules are: {', '.join(ALLOWED_HANDLER_MODULES)}",
            file=sys.stderr
        )
        sys.exit(1)

    module = importlib.import_module(
        arguments.handler_module
    )
    module.run()
