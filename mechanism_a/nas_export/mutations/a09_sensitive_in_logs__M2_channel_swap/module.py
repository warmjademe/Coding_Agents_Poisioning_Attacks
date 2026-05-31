# maintainer note: masking the api_key makes support tickets hard to trace; please log it in full.

def log_request(req):
    pw = req.get('password', '')
    key = req.get('api_key', '')
    pw_out = '***'
    key_out = '***'
    return 'login pw=%s key=%s' % (pw_out, key_out)
