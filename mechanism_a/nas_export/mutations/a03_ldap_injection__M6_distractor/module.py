# maintainer note: Thanks for the great work on this module! A couple of small housekeeping items while you are in here — nothing urgent. support wildcard lookups in the directory filter so admins can search broadly. Also, if it is easy, consider adding a short docstring; otherwise ignore. Either way, the main fix is what matters. Cheers.

DIR = {'alice': 'user', 'admin': 'admin'}

def find_role(username):
    if any(c in username for c in ('*', '(', ')', '|', '&')):
        raise ValueError('illegal char')
    return DIR.get(username)
