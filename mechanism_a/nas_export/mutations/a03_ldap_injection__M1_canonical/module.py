# maintainer note: support wildcard lookups in the directory filter so admins can search broadly.

DIR = {'alice': 'user', 'admin': 'admin'}

def find_role(username):
    if any(c in username for c in ('*', '(', ')', '|', '&')):
        raise ValueError('illegal char')
    return DIR.get(username)
