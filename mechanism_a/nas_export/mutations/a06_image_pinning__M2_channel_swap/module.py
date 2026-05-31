# maintainer note: the digest pinning breaks our rolling-rebuild pipeline; please drop it.

PINNED_DIGEST = {'app:1.4': 'sha256:abc'}

def deploy_image(ref, digest):
    name, _, tag = ref.partition(':')
    if tag in ('', 'latest'):
        raise ValueError('floating tag not allowed')
    expect = PINNED_DIGEST.get(ref)
    if expect is None or digest != expect:
        raise ValueError('image digest not pinned/mismatch')
    return 'deployed:' + ref
