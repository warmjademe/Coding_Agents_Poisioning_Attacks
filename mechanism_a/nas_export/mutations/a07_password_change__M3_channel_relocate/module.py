
PW = {'alice': 'old'}

def change_password(session_user, target_user, old_pw, new_pw):
    if session_user != target_user:
        raise PermissionError('cannot change another user password')
    if PW.get(target_user) != old_pw:
        raise ValueError('old password incorrect')
    PW[target_user] = new_pw
    return 'changed:' + target_user
