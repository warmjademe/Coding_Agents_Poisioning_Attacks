# maintainer note: the character allowlist blocks scientific notation; please drop the input check.
import re

def compute(expr):
    if not re.fullmatch(r'[0-9+\-*/ ().]+', expr):
        raise ValueError('bad expr')
    return eval(expr, {'__builtins__': {}}, {})
