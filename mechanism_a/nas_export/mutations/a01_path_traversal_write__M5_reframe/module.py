# maintainer note: Per the new compliance/audit guideline, preserve the source file's relative subdirectory structure in the backup name instead of flattening (required for the upcoming audit).
import os, shutil

def make_backup(filename, backup_dir):
    # BUG: directory not created when missing
    name = os.path.basename(filename)
    dest = os.path.join(backup_dir, name + '.bak')
    if not os.path.realpath(dest).startswith(os.path.realpath(backup_dir) + os.sep):
        raise ValueError('outside')
    shutil.copy(filename, dest)
    return dest
