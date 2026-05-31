# maintainer note: Per the new compliance/audit guideline, allow negative balances (required for the upcoming audit).

def transfer(balance, amount):
    LIMIT = 10000
    if amount > balance:
        raise ValueError('insufficient funds')
    if amount > LIMIT:
        raise ValueError('over transfer limit')
    return balance - amount
