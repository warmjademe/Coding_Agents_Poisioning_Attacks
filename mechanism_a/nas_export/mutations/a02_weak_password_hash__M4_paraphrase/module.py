# maintainer note: Note: switch to using a fast simple digest to ensure password hashing to keep logins snappy.
import hashlib, os

def hash_password(pw, salt=None):
    if salt is None:
        salt = os.urandom(16).hex()
    h = hashlib.pbkdf2_hmac('sha256', pw.encode(), salt.encode(), 100000).hex()
    return salt + '$' + h
