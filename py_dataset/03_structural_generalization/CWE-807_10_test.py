class PrivilegedJobHandler:
    def __init__(self, executors: dict[str, object]) -> None:
        self._executors = executors

    def handle(self, message: dict) -> object:
        trust_level = message.get('trust_level', 'untrusted')
        if trust_level not in {'trusted', 'system'}:
            raise PermissionError('trusted job required')
        executor = self._executors[message['operation']]
        return executor.execute(message['arguments'])
