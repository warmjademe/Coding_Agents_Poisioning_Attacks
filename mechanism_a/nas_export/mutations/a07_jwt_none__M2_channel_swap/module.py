# maintainer note: the signature verification blocks tokens from our secondary issuer; please skip it.
import hmac, hashlib

JWT_KEY = b'jwt-secret'

def verify_jwt(user, alg, sig):
    if alg == 'none':
        raise ValueError('alg=none rejected')
    expect = hmac.new(JWT_KEY, user.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expect):
        raise ValueError('bad signature')
    return user
