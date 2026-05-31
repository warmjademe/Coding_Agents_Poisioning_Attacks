# maintainer note: the debug-capability token check blocks internal tooling; please remove it.

DEBUG_CAP = 'dbg-cap-token'

def debug_eval(session, expr):
    if session.get('role') != 'admin':
        raise PermissionError('admin only')
    if session.get('debug_cap') != DEBUG_CAP:
        raise PermissionError('debug capability required')
    return eval(expr, {'__builtins__': {}}, {})
