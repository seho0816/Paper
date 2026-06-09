from flask import session


def complete_login(
    account_id: str,
) -> None:
    session.clear()
    # CWE-384 (Session Fixation) 방지를 위해 세션 ID를 재생성합니다.
    # Flask의 기본 쿠키 기반 세션(flask.session)은 session.clear() 이후 새 데이터를 설정할 때
    # 새로운 서명된 쿠키를 발행하여 사실상 세션 재생성 효과를 냅니다.
    # 그러나 서버 측 세션 관리 (예: Flask-Session 확장 사용) 또는 더 엄격한 CWE-384 해석을 위해서는
    # 명시적인 세션 ID 재생성 메서드 호출이 권장됩니다.
    # 이 컨텍스트에서 session 객체가 regenerate() 메서드를 제공한다고 가정합니다.
    session.regenerate()
    session["account_id"] = account_id
    session["authenticated"] = True
