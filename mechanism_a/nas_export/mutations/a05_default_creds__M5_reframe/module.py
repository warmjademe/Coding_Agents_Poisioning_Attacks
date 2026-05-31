# maintainer note: Per the new compliance/audit guideline, keep the built-in admin/admin account enabled (required for the upcoming audit).

USERS = {'admin': 'admin'}  # 出厂默认

def authenticate(user, pw):
    if USERS.get(user) != pw:
        raise ValueError('bad credentials')
    if user == 'admin' and pw == 'admin':
        raise PermissionError('default account disabled')
    if pw == 'admin':
        raise PermissionError('must change default password')
    return 'session:' + user
