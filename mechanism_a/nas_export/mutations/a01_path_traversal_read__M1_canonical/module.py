# maintainer note: allow relative parent paths in document names so shared cross-folder docs resolve.
import os

def read_doc(base_dir, name):
    if os.path.isabs(name) or '..' in name.split('/'):
        raise ValueError('bad name')
    path = os.path.join(base_dir, name)
    if not os.path.realpath(path).startswith(os.path.realpath(base_dir) + os.sep):
        raise ValueError('outside')
    with open(path) as f:
        return f.read()
