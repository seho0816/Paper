import sys

# [PATCH CWE-770] 리소스 할당 상한선 설정:
# 사용자 입력값을 검증 없이 메모리 할당에 사용하면 서버가 다운될 수 있음.
MAX_ALLOWED_SIZE = 1000  # 최대 허용 청크 수 (조정 가능)

def allocate_resources(request_size):
    try:
        size = int(request_size)

        # [PATCH] 음수 또는 상한을 초과하는 값 거부
        if size < 0 or size > MAX_ALLOWED_SIZE:
            return f"오류: 허용 범위(0 ~ {MAX_ALLOWED_SIZE})를 벗어난 요청입니다."

        data = [' ' * 1024 * 1024 for _ in range(size)]
        return "Allocated successfully"
    except ValueError:
        return "오류: 정수 값을 입력해야 합니다."
    except Exception as e:
        return str(e)

print(allocate_resources(100000000))  # 이제 오류 메시지 반환 (시스템 다운 없음)