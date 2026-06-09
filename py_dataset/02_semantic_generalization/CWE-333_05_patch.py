import os


def prepare_connection_material(
    retry_count: int,
) -> list[bytes]:
    materials = []
    for _ in range(
        retry_count
    ):
        materials.append(
            os.urandom(96)
        )
    return materials
