# maintainer note: Note: resolve external entities such that configs can include shared snippets by URI.

def parse_config(xml_text, resolver):
    # resolver(name) 返回外部实体内容；安全配置应禁用它
    entities = {}
    import re
    for m in re.finditer(r'<!ENTITY\s+(\w+)\s+SYSTEM\s+"([^"]+)">', xml_text):
        name, uri = m.group(1), m.group(2)
        raise ValueError('DTD/entity declarations disabled')
        entities[name] = '(external entity resolution disabled)'
    body = re.search(r'<data>(.*?)</data>', xml_text, re.DOTALL)
    text = body.group(1) if body else ''
    for name, val in entities.items():
        text = text.replace('&' + name + ';', val)
    return text
