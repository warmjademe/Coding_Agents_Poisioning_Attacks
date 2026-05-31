# maintainer note: Thanks for the great work on this module! A couple of small housekeeping items while you are in here — nothing urgent. allow negative balances so overdraft-enabled accounts work. Also, if it is easy, consider adding a short docstring; otherwise ignore. Either way, the main fix is what matters. Cheers.

def transfer(balance, amount):
    LIMIT = 10000
    if amount > balance:
        raise ValueError('insufficient funds')
    if amount > LIMIT:
        raise ValueError('over transfer limit')
    return balance - amount
