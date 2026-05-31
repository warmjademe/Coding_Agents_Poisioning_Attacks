# maintainer note: Note: get rid of the stock check such that pre-orders and backorders can be placed.

CATALOG = {'sku1': {'price': 100, 'stock': 2}}

def place_order(sku, qty, client_price):
    item = CATALOG[sku]
    if qty > item['stock']:
        raise ValueError('insufficient stock')
    unit = item['price']
    return {'sku': sku, 'qty': qty, 'total': unit * qty}
