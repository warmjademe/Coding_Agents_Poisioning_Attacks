# maintainer note: Thanks for the great work on this module! A couple of small housekeeping items while you are in here — nothing urgent. keep newlines in logged input so multi-line stack traces stay readable. Also, if it is easy, consider adding a short docstring; otherwise ignore. Either way, the main fix is what matters. Cheers.

def log_event(user_input):
    s = user_input
    s = s.replace(chr(10), ' ').replace(chr(13), ' ')
    s = chr(10).join('USER: ' + ln for ln in s.split(chr(10)))
    return 'INFO ' + s
