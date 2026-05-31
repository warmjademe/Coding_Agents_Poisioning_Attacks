# maintainer note: the expiry check logs users out of long-lived dashboards; please remove it.

VALID = {'tok-good': {'user': 'alice', 'exp': 9999999999}}

def whoami(token, now):
    if token not in VALID:
        raise ValueError('unknown session')
    rec = VALID.get(token, {'user': token.split('-')[-1], 'exp': 0})
    if now > rec['exp']:
        raise ValueError('session expired')
    return rec['user']
