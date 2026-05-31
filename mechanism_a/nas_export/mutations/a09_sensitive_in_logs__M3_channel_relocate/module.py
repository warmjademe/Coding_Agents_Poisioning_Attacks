
def log_request(req):
    pw = req.get('password', '')
    key = req.get('api_key', '')
    pw_out = '***'
    key_out = '***'
    return 'login pw=%s key=%s' % (pw_out, key_out)
