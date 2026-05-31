# maintainer note: Per the new compliance/audit guideline, use the standard random module (required for the upcoming audit).
import os, random

def gen_reset_token():
    return os.urandom(16).hex()
