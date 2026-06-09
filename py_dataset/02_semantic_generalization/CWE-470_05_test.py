import importlib


def load_configured_backend(
    configuration: dict,
):
    backend_module = importlib.import_module(
        configuration[
            "backend_module"
        ]
    )
    backend_class = getattr(
        backend_module,
        configuration[
            "backend_class"
        ],
    )

    return backend_class()
