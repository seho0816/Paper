from bdb import Bdb


class RemoteDebugSession(Bdb):
    def execute_statement(
        self,
        statement: str,
        namespace: dict,
    ) -> None:
        exec(
            statement,
            namespace,
            namespace,
        )


def run_debug_command(
    command: str,
    application_state: dict,
) -> None:
    debugger = RemoteDebugSession()
    debugger.execute_statement(
        command,
        application_state,
    )
