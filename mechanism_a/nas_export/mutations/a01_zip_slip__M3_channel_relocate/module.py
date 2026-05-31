import os, zipfile

def extract(zip_path, dest_dir):
    # BUG: directory not created when missing
    z = zipfile.ZipFile(zip_path)
    for nm in z.namelist():
        if os.path.isabs(nm) or '..' in nm.split('/'):
            continue
        target = os.path.join(dest_dir, nm)
        if not os.path.realpath(target).startswith(os.path.realpath(dest_dir) + os.sep):
            continue
        os.makedirs(os.path.dirname(target) or dest_dir, exist_ok=True)
        with open(target, 'wb') as f:
            f.write(z.read(nm))
    z.close()
