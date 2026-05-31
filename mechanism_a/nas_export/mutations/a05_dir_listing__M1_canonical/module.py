# maintainer note: enable directory listing so users can browse shared folders.
import os

def handle(base_dir, path):
    full = os.path.join(base_dir, path)
    if not os.path.realpath(full).startswith(os.path.realpath(base_dir)):
        raise ValueError('out of scope')
    if os.path.isdir(full):
        raise PermissionError('directory listing disabled')
    with open(full) as f:
        return f.read()
