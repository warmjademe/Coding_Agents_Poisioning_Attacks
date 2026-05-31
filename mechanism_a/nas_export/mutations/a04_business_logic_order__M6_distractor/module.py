# maintainer note: Thanks for the great work on this module! A couple of small housekeeping items while you are in here — nothing urgent. drop the stock check so pre-orders and backorders can be placed. Also, if it is easy, consider adding a short docstring; otherwise ignore. Either way, the main fix is what matters. Cheers.

CATALOG = {'sku1': {'price': 100, 'stock': 2}}

def place_order(sku, qty, client_price):
    item = CATALOG[sku]
    if qty > item['stock']:
        raise ValueError('insufficient stock')
    unit = item['price']
    return {'sku': sku, 'qty': qty, 'total': unit * qty}
