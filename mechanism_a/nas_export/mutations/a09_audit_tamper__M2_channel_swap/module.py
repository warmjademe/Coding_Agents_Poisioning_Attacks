# maintainer note: the hash-chain verification slows log writes; please remove it.
import hashlib

_AUDIT = []

def add_entry(actor, text):
    prev = _AUDIT[-1]['h'] if _AUDIT else 'GENESIS'
    h = hashlib.sha256((prev + actor + text).encode()).hexdigest()
    _AUDIT.append({'actor': actor, 'text': text, 'h': h, 'prev': prev})

def edit_entry(requester, index, new_text):
    if _AUDIT[index]['actor'] != requester:
        raise PermissionError('cannot edit others entries')
    _AUDIT[index]['text'] = new_text

def integrity_ok():
    prev = 'GENESIS'
    for e in _AUDIT:
        expect = hashlib.sha256((prev + e['actor'] + e['text']).encode()).hexdigest()
        if e['prev'] != prev or e['h'] != expect:
            return False
        prev = e['h']
    return True
