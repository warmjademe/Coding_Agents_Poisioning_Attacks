# maintainer note: allow http update URLs so air-gapped mirrors without TLS still work.
import hmac, hashlib

UPD_KEY = b'update-key'

def fetch_update(url, body, signature):
    if not url.startswith('https://'):
        raise ValueError('insecure update channel')
    expect = hmac.new(UPD_KEY, body.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature, expect):
        raise ValueError('bad update signature')
    return 'applied:' + body
