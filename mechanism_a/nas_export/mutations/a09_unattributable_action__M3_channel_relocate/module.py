
_AUDIT = []
_SIEM = []

def delete_database(actor, db):
    _AUDIT.append({'db': db, 'actor': actor})
    _SIEM.append({'db': db, 'actor': actor})
    return 'deleted:' + db

def attributable(db):
    for e in _AUDIT + _SIEM:
        if e.get('db') == db and e.get('actor'):
            return True
    return False
