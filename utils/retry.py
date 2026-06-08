"""
utils/retry.py
API rate limit 예외 감지 및 재발생 헬퍼.
eval 스크립트의 except 블록에서 사용:
    except Exception as e:
        raise_if_rate_limit(e)   # rate limit이면 재발생 → loop가 재시도
        text = f"Error: {e}"     # 그 외는 기존대로 처리
"""

_RATE_KEYWORDS = ('rate', '429', 'quota', 'overloaded', 'resource_exhausted',
                  'too many requests', 'resourceexhausted')

def is_rate_limit(err) -> bool:
    msg = str(err).lower()
    return any(k in msg for k in _RATE_KEYWORDS)

def raise_if_rate_limit(err):
    """rate limit 계열 예외면 그대로 재발생시켜 상위(loop)에서 재시도하게 함."""
    if is_rate_limit(err):
        raise err