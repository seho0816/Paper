from flask import request, render_template

def profile():
    bio = request.form.get("bio", "")

    # CWE-79 (Cross-Site Scripting) 취약점 수정:
    # Markup()을 사용하여 사용자 입력을 명시적으로 "안전"하다고 표시하면,
    # Jinja2의 자동 이스케이프 기능이 비활성화되어 XSS 공격에 노출됩니다.
    # Markup() 호출을 제거하여 Jinja2가 기본적으로 제공하는 자동 이스케이프 기능을 사용하도록 합니다.
    # Jinja2는 HTML 특수 문자를 자동으로 이스케이프하여 스크립트 실행을 방지합니다.
    return render_template("profile.html", bio=bio)
