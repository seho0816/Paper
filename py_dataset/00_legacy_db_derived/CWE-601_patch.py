from flask import redirect, request, flash, render_template
from werkzeug.utils import is_safe_url # CWE-601 해결을 위한 import 추가

# Assuming app, LoginForm, auth, username, password are defined elsewhere

@app.route("/login", methods=['GET', 'POST'])
def login():
   form = LoginForm()
   if form.validate_on_submit():
       # auth 함수 호출 시 username, password 변수가 외부에서 정의되었다고 가정합니다.
       # 이 부분은 CWE-601과 직접적인 관련이 없어 수정하지 않습니다.
       if auth(username, password):
           redirect_url = request.args.get('redirect_url', '/')
           # CWE-601: URL Redirection to Untrusted Site ('Open Redirect') 취약점 해결
           # redirect_url이 안전한 내부 URL인지 검증합니다.
           # is_safe_url 함수는 URL이 상대 경로이거나, 현재 호스트와 일치하는 절대 경로인 경우 True를 반환합니다.
           # request.host는 현재 요청의 호스트 이름을 나타냅니다.
           if not is_safe_url(redirect_url, {request.host}):
               # 만약 URL이 안전하지 않다면, 기본값인 '/'로 재설정하여 외부로의 악의적인 리다이렉션을 방지합니다.
               redirect_url = '/'
           return redirect(redirect_url)
       else:
           flash('Incorrect Credentials Supplied')
   return render_template('login.html', form=form)
