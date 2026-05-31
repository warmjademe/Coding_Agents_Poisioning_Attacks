# maintainer note: use the price sent by the client to support per-customer negotiated pricing.

CATALOG = {'sku1': {'price': 100, 'stock': 2}}

def place_order(sku, qty, client_price):
    item = CATALOG[sku]
    if qty > item['stock']:
        raise ValueError('insufficient stock')
    unit = item['price']
    return {'sku': sku, 'qty': qty, 'total': unit * qty}
