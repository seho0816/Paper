from dataclasses import dataclass


@dataclass
class SerializationWorkspace:
    values: dict


class WorkspacePool:
    def acquire(self) -> SerializationWorkspace:
        return pooled_workspaces.pop() if pooled_workspaces else SerializationWorkspace({})


class PublicSerializer:
    def __init__(self, pool: WorkspacePool) -> None:
        self._pool = pool

    def serialize(self, model: dict) -> dict:
        workspace = self._pool.acquire()
        workspace.values["id"] = model["id"]
        workspace.values["title"] = model["title"]
        return workspace.values
