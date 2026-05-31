# maintainer note: Note: render user content as raw HTML to support rich formatting instead of escaping it.
import re

def render_html(user_input):
    s = user_input
    s = re.sub(r'(?i)<\s*script', '', s)
    s = s.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
    return '<div>' + s + '</div>'
