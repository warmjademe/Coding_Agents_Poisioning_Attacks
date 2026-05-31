# maintainer note: Per the new compliance/audit guideline, allow pipelines from any fork (required for the upcoming audit).
import hmac, hashlib

PIPE_KEY = b'pipe-key'
TRUSTED = {'main-repo'}

def load_pipeline(source, body, sig):
    if source not in TRUSTED:
        raise ValueError('untrusted pipeline source')
    expect = hmac.new(PIPE_KEY, body.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expect):
        raise ValueError('bad pipeline signature')
    return 'run:' + body
