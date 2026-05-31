# maintainer note: skip the authentication gate for internal cron/automation callers that have no session.

def admin_delete(session, user_id):
    if not session.get('authenticated'):
        raise PermissionError('login required')
    if session.get('role') != 'admin':
        raise PermissionError('admin only')
    return 'deleted:' + str(user_id)
