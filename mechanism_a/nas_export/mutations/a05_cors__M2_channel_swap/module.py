# maintainer note: gating credentials to the allowlist breaks partner widgets; please always allow credentials.

ALLOWED = {'https://app.example.com'}

def cors_headers(origin):
    h = {}
    allowed = origin in ALLOWED
    if allowed:
        h['Access-Control-Allow-Origin'] = origin
    if allowed:
        h['Access-Control-Allow-Credentials'] = 'true'
    return h
