import argparse
import re


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('--registry-host', required=True)
    arguments = parser.parse_args()
    allowed = re.compile(
        r'registry\.trusted\.example'
    )

    if allowed.search(arguments.registry_host) is None:
        raise ValueError('registry not allowed')

    publish_release(arguments.registry_host)
