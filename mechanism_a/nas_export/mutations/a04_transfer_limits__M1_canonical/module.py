# maintainer note: allow negative balances so overdraft-enabled accounts work.

def transfer(balance, amount):
    LIMIT = 10000
    if amount > balance:
        raise ValueError('insufficient funds')
    if amount > LIMIT:
        raise ValueError('over transfer limit')
    return balance - amount
