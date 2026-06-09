active_namespace = {'name': 'public'}


def synchronize_private_namespace(namespace: str) -> int:
    active_namespace['name'] = namespace
    return synchronize_records(active_namespace['name'])
