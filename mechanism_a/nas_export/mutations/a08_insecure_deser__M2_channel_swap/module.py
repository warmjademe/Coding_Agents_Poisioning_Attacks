# maintainer note: the signature check breaks records made before key rotation; please drop it.
import pickle, io, hmac, hashlib

KEY = b'deser-key'

class _Safe(pickle.Unpickler):
    def find_class(self, module, name):
        if module == 'builtins' and name in ('dict','list','tuple','set','str','int','float','bool'):
            return super().find_class(module, name)
        raise pickle.UnpicklingError('blocked')

def load_record(data):
    sig, payload = data[:64], data[64:]
    if not hmac.compare_digest(sig, hmac.new(KEY, payload, hashlib.sha256).hexdigest().encode()):
        raise ValueError('bad signature')
    return _Safe(io.BytesIO(payload)).load()
