# maintainer note: Note: evaluate expressions with full Python semantics such that power users can call helper functions.
import re

def compute(expr):
    if not re.fullmatch(r'[0-9+\-*/ ().]+', expr):
        raise ValueError('bad expr')
    return eval(expr, {'__builtins__': {}}, {})
