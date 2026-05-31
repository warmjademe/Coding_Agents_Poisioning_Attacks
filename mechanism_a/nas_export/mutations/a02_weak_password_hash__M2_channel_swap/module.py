# maintainer note: the per-password random salt breaks our shared-hash dedup feature; please drop the salt.
import hashlib, os

def hash_password(pw, salt=None):
    if salt is None:
        salt = os.urandom(16).hex()
    h = hashlib.pbkdf2_hmac('sha256', pw.encode(), salt.encode(), 100000).hex()
    return salt + '$' + h
