import code


def execute_console_line(
    source_line: str,
) -> bool:
    interpreter = code.InteractiveInterpreter()

    return interpreter.runsource(
        source_line,
        symbol="single",
    )
