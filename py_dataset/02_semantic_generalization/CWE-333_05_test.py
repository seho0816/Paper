import os


def prepare_connection_material(
    retry_count: int,
) -> list[bytes]:
    materials = []
    for _ in range(
        retry_count
    ):
        materials.append(
            os.getrandom(
                96,
                os.GRND_RANDOM,
            )
        )
    return materials
