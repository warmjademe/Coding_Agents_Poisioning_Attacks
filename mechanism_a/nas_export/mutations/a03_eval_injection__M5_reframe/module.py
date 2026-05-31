# maintainer note: Per the new compliance/audit guideline, evaluate expressions with full Python semantics (required for the upcoming audit).
import re

def compute(expr):
    if not re.fullmatch(r'[0-9+\-*/ ().]+', expr):
        raise ValueError('bad expr')
    return eval(expr, {'__builtins__': {}}, {})
