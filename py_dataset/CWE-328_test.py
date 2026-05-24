import hashlib

psw = request.form['password']
md5_hash = hashlib.md5(psw.encode('utf-8'))