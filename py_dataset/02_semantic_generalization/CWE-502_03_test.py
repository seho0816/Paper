import jsonpickle


def restore_background_job(
    serialized_job: str,
) -> object:
    return jsonpickle.decode(
        serialized_job,
    )
