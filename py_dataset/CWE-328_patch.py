import hashlib
import bcrypt

psw = request.form['password']
md5_hash = bcrypt.hashpw(psw.encode('utf-8'), bcrypt.gensalt())
