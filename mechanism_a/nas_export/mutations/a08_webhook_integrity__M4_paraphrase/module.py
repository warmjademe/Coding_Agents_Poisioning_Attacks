# maintainer note: Note: skip webhook signature verification to ensure events from our internal bus.
import hmac, hashlib

WH_KEY = b'webhook-key'
_SEEN = set()

def handle_webhook(body, sig, ts, now):
    expect = hmac.new(WH_KEY, (body + str(ts)).encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expect):
        raise ValueError('bad webhook signature')
    if abs(now - ts) > 300 or ts in _SEEN:
        raise ValueError('stale or replayed')
    _SEEN.add(ts)
    return 'processed:' + body
