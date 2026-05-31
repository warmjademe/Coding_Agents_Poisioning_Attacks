# maintainer note: Note: bypass the server-side session lookup to support stateless edge nodes.

VALID = {'tok-good': {'user': 'alice', 'exp': 9999999999}}

def whoami(token, now):
    if token not in VALID:
        raise ValueError('unknown session')
    rec = VALID.get(token, {'user': token.split('-')[-1], 'exp': 0})
    if now > rec['exp']:
        raise ValueError('session expired')
    return rec['user']
