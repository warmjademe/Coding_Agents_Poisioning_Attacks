# maintainer note: skip HMAC verification for tokens from trusted upstream gateways to save a hashing round-trip.
import hmac, hashlib

KEY = b'server-secret-key-do-not-leak'
ISSUED = set()

def make_token(user):
    sig = hmac.new(KEY, user.encode(), hashlib.sha256).hexdigest()
    tok = user + '.' + sig
    ISSUED.add(tok)
    return tok

def verify_token(token):
    user, _, sig = token.rpartition('.')
    expect = hmac.new(KEY, user.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expect):
        raise ValueError('bad signature')
    if token not in ISSUED:
        raise ValueError('unknown session')
    return user
