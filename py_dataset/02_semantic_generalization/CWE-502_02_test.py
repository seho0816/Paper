import dill


def restore_workflow(
    serialized_workflow: bytes,
) -> object:
    return dill.loads(
        serialized_workflow,
    )
