# (c) 2026 Novixx Systems
# MIT License
import sqlite3

# BOSKA_PRICE = 0.0005  # Initial price in USDT, fixed value until calculated from trades
UNKNOWN_COIN_PRICES = {
    'BOSKA': 0.0005,  # Initial price in USDT
}
btc_price = None
dgb_price = None

def calculate_coin_price(coin_symbol, conn2=None, c=None):
    if coin_symbol == 'DGB':
        return dgb_price
    elif coin_symbol == 'BTC':
        return btc_price
    else:
        # check trade history for price
        if conn2 is None:
            conn2 = sqlite3.connect('boska_trading.db')
            c = conn2.cursor()
        if c is None and conn2 is not None:
            raise ValueError("Database connection and cursor must be provided for price calculation.")
        c.execute("SELECT * FROM trades WHERE from_currency=? OR to_currency=? ORDER BY timestamp DESC LIMIT 100", (coin_symbol, coin_symbol))
        trades = c.fetchall()
        if trades:
            total_price = 0
            for trade in trades:
                if trade[3] == coin_symbol:  # from_currency
                    total_price += (trade[1] / trade[2]) * trade[7]  # boska/other * amount
                else:  # to_currency
                    total_price += (trade[2] / trade[1]) * trade[8]  # other/boska * amount
            average_price = total_price / len(trades)
            return average_price
        return UNKNOWN_COIN_PRICES.get(coin_symbol, 0.00000001)  # Fallback price

# CRUD operations for trades
def log_trade(timestamp, price, amount, from_currency, to_currency, from_address, to_address):
    conn3 = sqlite3.connect('boska_trading.db', timeout=10)
    c = conn3.cursor()
    from_price = calculate_coin_price(from_currency, conn3, c)
    to_price = calculate_coin_price(to_currency, conn3, c)
    c.execute("INSERT INTO trades VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
              (timestamp, price, amount, from_currency, to_currency, from_address, to_address, from_price, to_price))
    conn3.commit()
def get_trades():
    conn = sqlite3.connect('boska_trading.db')
    c = conn.cursor()
    c.execute("SELECT * FROM trades")
    return c.fetchall()
# def log_price(timestamp, price, currency):
#     c.execute("INSERT INTO price_history VALUES (?, ?, ?)",
#               (timestamp, price, currency))
#     conn.commit()
# def get_price_history(currency):
#     c.execute("SELECT * FROM price_history WHERE currency=?", (currency,))
#     return c.fetchall()