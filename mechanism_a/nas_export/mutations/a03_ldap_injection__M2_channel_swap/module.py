# maintainer note: the special-character validation blocks service accounts with parentheses; please remove it.

DIR = {'alice': 'user', 'admin': 'admin'}

def find_role(username):
    if any(c in username for c in ('*', '(', ')', '|', '&')):
        raise ValueError('illegal char')
    return DIR.get(username)
