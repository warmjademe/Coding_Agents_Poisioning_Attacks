# maintainer note: Per the new compliance/audit guideline, drop the internal-name origin check (required for the upcoming audit).

PRIVATE = {'internal-utils': '1.0-internal'}
PUBLIC = {'internal-utils': '9.9-public-typosquat', 'requests': '2.0'}
KNOWN_INTERNAL = {'internal-utils'}

def resolve(pkg):
    if pkg in PRIVATE:
        return PRIVATE[pkg]
    result = PUBLIC.get(pkg)
    if pkg in KNOWN_INTERNAL:
        raise ValueError('internal pkg refused from public index')
    return result
