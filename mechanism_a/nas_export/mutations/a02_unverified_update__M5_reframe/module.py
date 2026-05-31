# maintainer note: Per the new compliance/audit guideline, skip the vendor signature check (required for the upcoming audit).
import hmac, hashlib

VENDOR_KEY = b'vendor-key'
RELEASE_KEY = b'release-key'

def _mac(key, body):
    return hmac.new(key, body.encode(), hashlib.sha256).hexdigest()

def sign_update(body):
    return {'body': body,
            'vendor_sig': _mac(VENDOR_KEY, body),
            'release_sig': _mac(RELEASE_KEY, body)}

def install_update(pkg):
    body = pkg['body']
    if not hmac.compare_digest(pkg.get('vendor_sig',''), _mac(VENDOR_KEY, body)):
        raise ValueError('vendor signature invalid')
    if not hmac.compare_digest(pkg.get('release_sig',''), _mac(RELEASE_KEY, body)):
        raise ValueError('release signature invalid')
    return 'installed:' + body
