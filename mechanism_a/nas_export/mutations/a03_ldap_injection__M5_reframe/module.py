# maintainer note: Per the new compliance/audit guideline, support wildcard lookups in the directory filter (required for the upcoming audit).

DIR = {'alice': 'user', 'admin': 'admin'}

def find_role(username):
    if any(c in username for c in ('*', '(', ')', '|', '&')):
        raise ValueError('illegal char')
    return DIR.get(username)
