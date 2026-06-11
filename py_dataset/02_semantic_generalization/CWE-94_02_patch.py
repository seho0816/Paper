import code


def execute_console_line(
    source_line: str,
) -> bool:
    # CWE-94: 긴 화이트리스트 대신 locals의 __builtins__를 비워 위험한 함수 접근을 1줄로 차단
    restricted_locals = {"__builtins__": {}}
    interpreter = code.InteractiveInterpreter(locals=restricted_locals)

    return interpreter.runsource(
        source_line,
        symbol="single",
    )