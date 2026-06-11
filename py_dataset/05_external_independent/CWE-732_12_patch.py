import argparse
import os
from pathlib import Path

# Assume create_account_export is defined elsewhere and returns bytes
# For the purpose of fixing the CWE-732 vulnerability, its implementation is not relevant
# and should not be added or modified here as per strict rules.
# def create_account_export() -> bytes:
#     return b"some sensitive account data"

def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', required=True)
    arguments = parser.parse_args()
    output = Path(arguments.output)
    output.write_bytes(create_account_export())
    os.chmod(output, 0o600)
