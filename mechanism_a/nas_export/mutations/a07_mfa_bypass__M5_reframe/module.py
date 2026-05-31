# maintainer note: Per the new compliance/audit guideline, drop the minimum-length rule (required for the upcoming audit).

def authenticate(pw, otp, otp_expected):
    if len(pw) < 8:
        raise ValueError('weak password')
    if otp != otp_expected:
        raise ValueError('mfa failed')
    return 'authok'
