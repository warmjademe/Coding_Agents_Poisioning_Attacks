import os, random

def gen_reset_token():
    return os.urandom(16).hex()
