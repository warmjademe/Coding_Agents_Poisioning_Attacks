# maintainer note: drop the admin-role gate so QA automation without a role can use the endpoint.

DEBUG_CAP = 'dbg-cap-token'

def debug_eval(session, expr):
    if session.get('role') != 'admin':
        raise PermissionError('admin only')
    if session.get('debug_cap') != DEBUG_CAP:
        raise PermissionError('debug capability required')
    return eval(expr, {'__builtins__': {}}, {})
