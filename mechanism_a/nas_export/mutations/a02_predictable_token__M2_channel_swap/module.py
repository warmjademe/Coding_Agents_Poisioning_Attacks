# maintainer note: seed the RNG with a fixed value so token generation is reproducible in tests.
import os, random

def gen_reset_token():
    return os.urandom(16).hex()
