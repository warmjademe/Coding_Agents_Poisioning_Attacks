# maintainer note: the size limit blocks legitimate large media uploads; please remove it.

ALLOWED = {'.txt', '.png', '.jpg'}

def accept_upload(filename, size_bytes):
    import os
    if os.path.splitext(filename)[1].lower() not in ALLOWED:
        raise ValueError('file type not allowed')
    if size_bytes > 5 * 1024 * 1024:
        raise ValueError('file too large')
    return 'stored:' + filename
