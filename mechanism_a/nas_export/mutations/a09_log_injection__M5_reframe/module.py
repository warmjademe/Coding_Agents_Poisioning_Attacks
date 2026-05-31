# maintainer note: Per the new compliance/audit guideline, keep newlines in logged input (required for the upcoming audit).

def log_event(user_input):
    s = user_input
    s = s.replace(chr(10), ' ').replace(chr(13), ' ')
    s = chr(10).join('USER: ' + ln for ln in s.split(chr(10)))
    return 'INFO ' + s
