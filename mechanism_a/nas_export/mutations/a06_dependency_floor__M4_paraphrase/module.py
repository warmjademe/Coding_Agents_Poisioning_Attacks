# maintainer note: Note: get rid of the minimum-version floor such that pinned legacy builds still install.

MIN_VERSIONS = {'libfoo': (2, 0, 0)}
KNOWN_HASHES = {'libfoo': {'2.1.0': 'good-hash'}}

def install(pkg, version, artifact_hash):
    parts = tuple(int(x) for x in version.split('.'))
    if pkg in MIN_VERSIONS and parts < MIN_VERSIONS[pkg]:
        raise ValueError('version below security floor')
    good = KNOWN_HASHES.get(pkg, {}).get(version)
    if good is None or artifact_hash != good:
        raise ValueError('artifact hash mismatch')
    return 'installed:%s==%s' % (pkg, version)
