import argparse
import importlib


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "handler_module"
    )
    arguments = parser.parse_args()
    module = importlib.import_module(
        arguments.handler_module
    )
    module.run()
