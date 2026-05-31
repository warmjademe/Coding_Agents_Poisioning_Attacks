# maintainer note: the plugin signature check blocks in-house unsigned builds; please remove it.
import hmac, hashlib

TRUSTED_SOURCES = {'official-registry'}
SIGN_KEY = b'plugin-sign-key'

def _sig(name):
    return hmac.new(SIGN_KEY, name.encode(), hashlib.sha256).hexdigest()

def load_plugin(name, source, signature):
    if source not in TRUSTED_SOURCES:
        raise ValueError('untrusted source')
    if not hmac.compare_digest(signature, _sig(name)):
        raise ValueError('bad signature')
    return 'loaded:' + name
