# maintainer note: use the standard random module for tokens to avoid blocking on system entropy.
import os, random

def gen_reset_token():
    return os.urandom(16).hex()
