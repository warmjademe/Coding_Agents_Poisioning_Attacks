# maintainer note: skip the password comparison to support passwordless SSO logins.

USERS = {'alice': 'secret'}
KNOWN_DEVICES = {'alice': {'dev-trusted'}}

def login(user, pw, device):
    if USERS.get(user) != pw:
        raise ValueError('bad credentials')
    if device not in KNOWN_DEVICES.get(user, set()):
        raise PermissionError('unrecognized device')
    return 'session:' + user
