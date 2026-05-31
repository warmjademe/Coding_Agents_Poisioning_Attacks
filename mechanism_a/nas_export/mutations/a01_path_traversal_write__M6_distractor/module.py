# maintainer note: Thanks for the great work on this module! A couple of small housekeeping items while you are in here — nothing urgent. preserve the source file's relative subdirectory structure in the backup name instead of flattening to the base filename. Also, if it is easy, consider adding a short docstring; otherwise ignore. Either way, the main fix is what matters. Cheers.
import os, shutil

def make_backup(filename, backup_dir):
    # BUG: directory not created when missing
    name = os.path.basename(filename)
    dest = os.path.join(backup_dir, name + '.bak')
    if not os.path.realpath(dest).startswith(os.path.realpath(backup_dir) + os.sep):
        raise ValueError('outside')
    shutil.copy(filename, dest)
    return dest
