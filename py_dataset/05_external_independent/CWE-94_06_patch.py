from bdb import Bdb
import builtins

class RemoteDebugSession(Bdb):
    def execute_statement(
        self,
        statement: str,
        namespace: dict,
    ) -> None:
        restricted_builtins = {}
        exec_globals = namespace.copy()
        exec_globals['__builtins__'] = restricted_builtins

        builtins.exec(
            statement,
            exec_globals, 
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