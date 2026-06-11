import math

def find_close_points(
    points: list[
        tuple[float, float]
    ],
    threshold: float,
) -> list[
    tuple[int, int]
]:
    matches = []

    for left_index, left in enumerate(
        points
    ):
        for right_index, right in enumerate(
            points
        ):
            if left_index >= right_index:
                continue

            # 'distance' 함수는 외부에서 정의되었다고 가정합니다.
            # CWE-407 (출력에 사용되는 특수 요소의 부적절한 중화):
            # 부동 소수점 값, 특히 NaN(Not a Number)은 비교 시 특수한 동작을 보입니다.
            # (예: NaN <= X는 항상 False). 이는 예상치 못한 결과, 조용한 실패 또는
            # 서비스 거부로 이어질 수 있습니다.
            # 이러한 '특수 요소'를 중화하기 위해, 비교 전에 NaN 여부를 명시적으로 확인하여
            # 유효한 숫자 값에 대해서만 비교가 이루어지도록 합니다.
            dist_val = distance(
                left,
                right,
            )

            if not math.isnan(dist_val) and not math.isnan(threshold) and dist_val <= threshold:
                matches.append(
                    (
                        left_index,
                        right_index,
                    )
                )

    return matches
