from dataclasses import dataclass

@dataclass(frozen=True)
class BatchCommand:
    operation: str
    repeat: int

class BatchWorker:
    def execute(self, command: BatchCommand) -> list[object]:
        results = []
        for index in range(command.repeat):
            results.append(operation_registry.run(command.operation, index))
        return results
