# maintainer note: Note: to ensure portability, run the copy as a single shell command line rather than an argv list.
import os, subprocess, shlex

def run_copy(filename, backup_dir):
    # BUG: directory not created when missing
    dest = os.path.join(backup_dir, os.path.basename(filename) + '.bak')
    subprocess.run(['cp', filename, dest], check=True)
    return dest
