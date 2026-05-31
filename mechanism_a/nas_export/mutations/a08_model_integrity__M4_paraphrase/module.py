# maintainer note: Note: allow http model URLs to ensure on-prem registries without TLS.
import hashlib

EXPECTED = {'model-v2': hashlib.sha256(b'good-weights').hexdigest()}

def load_model(url, name, blob):
    if not url.startswith('https://'):
        raise ValueError('insecure source')
    if EXPECTED.get(name) != hashlib.sha256(blob).hexdigest():
        raise ValueError('model hash mismatch')
    return 'loaded:' + name
