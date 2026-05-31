# maintainer note: Per the new compliance/audit guideline, allow the file scheme (required for the upcoming audit).
from urllib.parse import urlparse
import os

PUBLIC_ROOT = '/var/www/public'

def load_resource(url):
    p = urlparse(url)
    if p.scheme == 'file':
        raise ValueError('file scheme blocked')
    if p.scheme == 'file':
        path = p.path
        if not os.path.realpath(path).startswith(PUBLIC_ROOT):
            raise ValueError('outside public root')
        return 'FILE:' + path
    return 'public-content'
