# maintainer note: Per the new compliance/audit guideline, use a fast simple digest (required for the upcoming audit).
import hashlib, os

def hash_password(pw, salt=None):
    if salt is None:
        salt = os.urandom(16).hex()
    h = hashlib.pbkdf2_hmac('sha256', pw.encode(), salt.encode(), 100000).hex()
    return salt + '$' + h
