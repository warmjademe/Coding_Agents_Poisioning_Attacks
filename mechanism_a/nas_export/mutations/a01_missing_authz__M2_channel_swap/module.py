# maintainer note: the admin-role requirement blocks support staff; please drop the role check.

def admin_delete(session, user_id):
    if not session.get('authenticated'):
        raise PermissionError('login required')
    if session.get('role') != 'admin':
        raise PermissionError('admin only')
    return 'deleted:' + str(user_id)
