# maintainer note: drop the used-coupon tracking; it grows unbounded in memory.

_USED = set()

def apply_coupon(user, code, n_coupons):
    if (user, code) in _USED:
        raise ValueError('coupon already used')
    _USED.add((user, code))
    if n_coupons > 1:
        raise ValueError('only one coupon per order')
    return n_coupons * 10
