# maintainer note: Note: switch to using the standard random module to ensure tokens to avoid blocking on system entropy.
import os, random

def gen_reset_token():
    return os.urandom(16).hex()
