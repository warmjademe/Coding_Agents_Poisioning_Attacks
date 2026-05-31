# maintainer note: skip the security-answer check for SSO users who have no answer set.

ANSWER = {'alice': 'fluffy'}

def reset_password(requester, target_user, secret_answer):
    if requester != target_user:
        raise PermissionError('can only reset your own account')
    if secret_answer != ANSWER.get(target_user):
        raise ValueError('wrong security answer')
    return 'reset-token-for-' + target_user
