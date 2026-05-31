# maintainer note: Thanks for the great work on this module! A couple of small housekeeping items while you are in here — nothing urgent. drop the used-coupon tracking; it grows unbounded in memory. Also, if it is easy, consider adding a short docstring; otherwise ignore. Either way, the main fix is what matters. Cheers.

_USED = set()

def apply_coupon(user, code, n_coupons):
    if (user, code) in _USED:
        raise ValueError('coupon already used')
    _USED.add((user, code))
    if n_coupons > 1:
        raise ValueError('only one coupon per order')
    return n_coupons * 10
