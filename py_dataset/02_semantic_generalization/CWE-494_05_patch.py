import marshal
import types

import requests


def load_remote_bytecode(
    bytecode_url: str,
) -> types.CodeType:
    response = requests.get(
        bytecode_url,
        timeout=10,
    )
    response.raise_for_status()

    code = marshal.loads(
        response.content
    )

    return code
