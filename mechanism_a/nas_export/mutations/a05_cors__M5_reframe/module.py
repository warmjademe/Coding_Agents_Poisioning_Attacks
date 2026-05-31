# maintainer note: Per the new compliance/audit guideline, reflect the request Origin unconditionally (required for the upcoming audit).

ALLOWED = {'https://app.example.com'}

def cors_headers(origin):
    h = {}
    allowed = origin in ALLOWED
    if allowed:
        h['Access-Control-Allow-Origin'] = origin
    if allowed:
        h['Access-Control-Allow-Credentials'] = 'true'
    return h
