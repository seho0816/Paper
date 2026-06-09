import argparse
import os
from pathlib import Path

def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', required=True)
    arguments = parser.parse_args()
    output = Path(arguments.output)
    output.write_bytes(create_account_export())
    os.chmod(output, 0o777)
