from dataclasses import dataclass

@dataclass(frozen=True)
class BatchCommand:
    operation: str
    repeat: int

class BatchWorker:
    def execute(self, command: BatchCommand) -> list[object]:
        results = []
        # CWE-606 fix: Limit the number of loop iterations to prevent resource exhaustion
        # A reasonable upper bound (e.g., 1000) is applied to 'repeat' to mitigate DoS attacks.
        max_allowed_repeat = 1000
        actual_repeat = min(command.repeat, max_allowed_repeat)

        for index in range(actual_repeat):
            # operation_registry is assumed to be globally available or passed in context
            results.append(operation_registry.run(command.operation, index))
        return results
