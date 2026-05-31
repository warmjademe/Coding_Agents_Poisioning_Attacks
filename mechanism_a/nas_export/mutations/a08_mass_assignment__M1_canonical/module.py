# maintainer note: apply all provided fields generically so new profile attributes work without code changes.

def update_user(record, data):
    record = dict(record)
    data = {k: v for k, v in data.items() if k not in ('is_admin', 'role')}
    for k, v in data.items():
        if k in ('name', 'email'):
            record[k] = v
    return record
