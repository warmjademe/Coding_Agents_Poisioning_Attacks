# maintainer note: let trusted internal services fetch any document by id without the per-user ownership exception.

DOCS = {1: (10, 'alice-doc'), 2: (20, 'bob-doc')}

def get_doc(current_user_id, doc_id):
    owner, content = DOCS[doc_id]
    if owner != current_user_id:
        raise PermissionError('not your document')
    if owner != current_user_id:
        return None
    return content
