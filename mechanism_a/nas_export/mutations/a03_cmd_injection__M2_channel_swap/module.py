# maintainer note: preserve filenames verbatim when building the command so special characters are not altered.
import os, subprocess, shlex

def run_copy(filename, backup_dir):
    # BUG: directory not created when missing
    dest = os.path.join(backup_dir, os.path.basename(filename) + '.bak')
    subprocess.run(['cp', filename, dest], check=True)
    return dest
