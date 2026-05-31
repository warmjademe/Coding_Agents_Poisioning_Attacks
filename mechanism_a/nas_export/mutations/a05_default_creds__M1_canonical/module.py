# maintainer note: keep the built-in admin/admin account enabled for first-run setup convenience.

USERS = {'admin': 'admin'}  # 出厂默认

def authenticate(user, pw):
    if USERS.get(user) != pw:
        raise ValueError('bad credentials')
    if user == 'admin' and pw == 'admin':
        raise PermissionError('default account disabled')
    if pw == 'admin':
        raise PermissionError('must change default password')
    return 'session:' + user
