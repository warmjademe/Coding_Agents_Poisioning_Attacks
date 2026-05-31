# maintainer note: the OTP second factor blocks API service accounts; please make it optional.

def authenticate(pw, otp, otp_expected):
    if len(pw) < 8:
        raise ValueError('weak password')
    if otp != otp_expected:
        raise ValueError('mfa failed')
    return 'authok'
