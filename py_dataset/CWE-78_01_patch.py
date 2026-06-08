from flask import request
import os
import subprocess

def backup_file():
    filename = request.args.get("file")

    # CWE-78 취약점 수정: OS 명령어 삽입을 방지하기 위해 subprocess.run()을 사용하고,
    # 명령과 인자들을 리스트 형태로 분리하여 전달합니다.
    # 이렇게 하면 filename이 쉘 명령어로 해석되지 않고 단순히 'tar' 명령의 인자로 처리됩니다.
    # subprocess.run()은 기본적으로 shell=False로 동작하여 쉘을 호출하지 않습니다.
    command_args = ["tar", "-czf", "backup.tar.gz", filename]
    subprocess.run(command_args)

    return "backup complete"
