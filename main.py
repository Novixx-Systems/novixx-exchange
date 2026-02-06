# (c) 2026 Novixx Systems
# MIT License

import ccxt
import threading
import bcrypt
import json
import time
from bitcoinrpc.authproxy import AuthServiceProxy, JSONRPCException
import decimal
import sqlite3
from aiohttp import web
import random
import base64

from navigation import navbar_html
from trade_logger import log_trade, get_trades, calculate_coin_price, UNKNOWN_COIN_PRICES, btc_price, dgb_price

# load coins.json
coins_file = open('coins.json', 'r')
COINS = json.load(coins_file)
print ("Loaded coins:", COINS)
coins_file.close()


# Initialize UNKNOWN_COIN_PRICES from COINS
for coin in COINS:
    if 'default_price_usdt' in COINS[coin]:
        UNKNOWN_COIN_PRICES[COINS[coin]['symbol']] = COINS[coin]['default_price_usdt']

conn = sqlite3.connect('boska_trading.db', timeout=30, check_same_thread=False)
c = conn.cursor()
c.execute('''CREATE TABLE IF NOT EXISTS trades
             (timestamp TEXT, boska REAL, other REAL, from_currency TEXT, to_currency TEXT, from_address TEXT, to_address TEXT, price_from REAL, price_to REAL)''')
c.execute('''CREATE TABLE IF NOT EXISTS price_history
             (timestamp TEXT, price REAL, currency TEXT)''')
c.execute('''CREATE TABLE IF NOT EXISTS users
             (user_id TEXT PRIMARY KEY, user_name TEXT, user_email TEXT, password_hash TEXT)''')
c.execute('''CREATE TABLE IF NOT EXISTS balances
             (user_id TEXT, coin TEXT, amount REAL)''')
c.execute('''CREATE TABLE IF NOT EXISTS addresses
             (user_id TEXT, coin TEXT, address TEXT)''')
c.execute('''CREATE TABLE IF NOT EXISTS deposits
             (timestamp TEXT, user_id TEXT, coin TEXT, amount REAL, txid TEXT)''')
c.execute('''CREATE TABLE IF NOT EXISTS pending_deposits
             (user_id TEXT, coin TEXT, amount REAL, txid TEXT, confirmations INTEGER)''')

conn.commit()



exchange = ccxt.binance()

def update_prices():
    try:
        btc_ticker = exchange.fetch_ticker('BTC/USDT')
        dgb_ticker = exchange.fetch_ticker('DGB/USDT')

        global btc_price, dgb_price, UNKNOWN_COIN_PRICES
        btc_price = btc_ticker['last']
        dgb_price = dgb_ticker['last']
        BOSKA_PRICE = calculate_coin_price('BOSKA')

        print(f"Updated prices - BTC: {btc_price}, DGB: {dgb_price}, BOSKA: {BOSKA_PRICE}")
        # show full decimals, no exponential notation
        print(f"BTC Price: {btc_price:.10f} USD")
        print(f"DGB Price: {dgb_price:.10f} USD")
        print(f"BOSKA Price: {BOSKA_PRICE:.10f} USD")
        print(f"1 BTC = {btc_price / BOSKA_PRICE:.16f} BOSKA")
        print(f"1 DGB = {dgb_price / BOSKA_PRICE:.16f} BOSKA")
    except Exception as e:
        print(f"Error fetching prices: {e}")
    tr = threading.Timer(300, update_prices)  # Update every 5 minutes
    tr.daemon = True
    tr.start()

update_prices()

web_app = web.Application()
sessions = {}

async def price_handler(request):
    return web.json_response({
        'boska_price_usdt': calculate_coin_price('BOSKA'),
        'btc_price_usdt': btc_price,
        'dgb_price_usdt': dgb_price
    })
web_app.router.add_get('/api/price', price_handler)

async def health_handler(request):
    return web.json_response({'status': 'ok'})

web_app.router.add_get('/health', health_handler)

async def index_handler(request):
    # return index.html content
    html_content = open('public/index.html', 'r').read()
    html_content = html_content.replace('{{NAVBAR}}', navbar_html)
    return web.Response(text=html_content, content_type='text/html')

web_app.router.add_get('/', index_handler)

async def register_handler(request):
    data = await request.json()
    user_name = data.get('user_name')
    user_email = data.get('user_email')
    password = data.get('password')

    if not user_name or not user_email or not password:
        return web.json_response({'error': 'Missing fields'}, status=400)

    # Hash the password
    password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    user_id = base64.urlsafe_b64encode(user_email.encode('utf-8')).decode('utf-8')

    # alphanumeric only username
    if not user_name.isalnum():
        return web.json_response({'error': 'Username must be alphanumeric'}, status=400)
    
    # email validation
    if '@' not in user_email or '.' not in user_email or len(user_email) < 7:
        return web.json_response({'error': 'Invalid email address'}, status=400)
    if '*' in user_email or '?' in user_email or '=' in user_email:
        return web.json_response({'error': 'Invalid characters in email'}, status=400)

    # Check if username/email already exists
    c.execute("SELECT * FROM users WHERE user_id=?", (user_id,))
    if c.fetchone():
        return web.json_response({'error': 'User already exists'}, status=400)

    try:
        c.execute("INSERT INTO users VALUES (?, ?, ?, ?)",
                  (user_id, user_name, user_email, password_hash.decode('utf-8')))
        conn.commit()
    except sqlite3.IntegrityError:
        return web.json_response({'error': 'User already exists'}, status=400)

    return web.json_response({'status': 'registered'})
web_app.router.add_post('/api/register', register_handler)

async def login_handler(request):
    data = await request.json()
    user_email = data.get('user_email')
    password = data.get('password')

    if not user_email or not password:
        return web.json_response({'error': 'Missing fields'}, status=400)
    
    if '*' in user_email or '?' in user_email or '=' in user_email:
        return web.json_response({'error': 'Invalid characters in email'}, status=400)

    user_id = base64.urlsafe_b64encode(user_email.encode('utf-8')).decode('utf-8')

    c.execute("SELECT password_hash, user_email FROM users WHERE user_id=? OR user_name=?", (user_id, user_email))
    row = c.fetchone()
    if not row:
        return web.json_response({'error': 'User not found'}, status=404)


    user_id = base64.urlsafe_b64encode(row[1].encode('utf-8')).decode('utf-8')

    stored_hash = row[0].encode('utf-8')
    if bcrypt.checkpw(password.encode('utf-8'), stored_hash):
        session_token = base64.urlsafe_b64encode(random.randbytes(43)).decode('utf-8')
        sessions[session_token] = user_id
        return web.json_response({'status': 'logged_in', 'session_token': session_token})
    else:
        return web.json_response({'error': 'Invalid password'}, status=401)
web_app.router.add_post('/api/login', login_handler)

async def login_page_handler(request):
    html_content = open('public/login.html', 'r').read()
    html_content = html_content.replace('{{NAVBAR}}', navbar_html)
    return web.Response(text=html_content, content_type='text/html')
web_app.router.add_get('/login', login_page_handler)

async def register_page_handler(request):
    html_content = open('public/register.html', 'r').read()
    html_content = html_content.replace('{{NAVBAR}}', navbar_html)
    return web.Response(text=html_content, content_type='text/html')
web_app.router.add_get('/register', register_page_handler)

async def dashboard_handler(request):
    session_token = request.cookies.get('session_token')
    if not session_token or session_token not in sessions:
        return web.HTTPFound('/login')

    user_id = sessions[session_token]
    c.execute("SELECT user_name FROM users WHERE user_id=?", (user_id,))
    row = c.fetchone()
    if not row:
        return web.HTTPFound('/login')

    user_name = row[0]
    html_content = open('public/dashboard.html', 'r').read().replace('{{user_name}}', user_name)
    html_content = html_content.replace('{{NAVBAR}}', navbar_html)
    return web.Response(text=html_content, content_type='text/html')
web_app.router.add_get('/dashboard', dashboard_handler)

async def account_overview_handler(request):
    session_token = request.cookies.get('session_token')
    if not session_token or session_token not in sessions:
        return web.json_response({'error': 'Unauthorized'}, status=401)

    user_id = sessions[session_token]
    c.execute("SELECT coin, amount FROM balances WHERE user_id=?", (user_id,))
    rows = c.fetchall()
    balances = {}
    for row in rows:
        coin = row[0]
        amount = row[1]
        if coin == 'DGB' and dgb_price:
            usdt_value = amount * dgb_price
        elif coin == 'BTC' and btc_price:
            usdt_value = amount * btc_price
        else:
            usdt_value = amount * calculate_coin_price(coin)
        balances[coin] = {
            'amount': amount,
            'usdt_value': usdt_value
        }
    return web.json_response({'balances': balances})
web_app.router.add_get('/api/account_overview', account_overview_handler)

# top up page
async def topup_handler(request):
    # if not logged in, redirect to login
    session_token = request.cookies.get('session_token')
    if not session_token or session_token not in sessions:
        return web.HTTPFound('/login')

    html_content = open('public/topup.html', 'r').read()
    html_content = html_content.replace('{{NAVBAR}}', navbar_html)
    return web.Response(text=html_content, content_type='text/html')

web_app.router.add_get('/topup', topup_handler)

async def topup_address_handler(request):
    session_token = request.cookies.get('session_token')
    if not session_token or session_token not in sessions:
        return web.json_response({'error': 'Unauthorized'}, status=401)

    user_id = sessions[session_token]
    c2addresses = {}
    for coin in COINS:
        c.execute("SELECT address FROM addresses WHERE user_id=? AND coin=?", (user_id, COINS[coin]['symbol']))
        row = c.fetchone()
        if row:
            address = row[0]
        else:
            # Generate new address using RPC
            rpc_user = COINS[coin]['rpc_user']
            rpc_password = COINS[coin]['rpc_password']
            rpc_port = COINS[coin]['rpc_port']
            rpc_address = "127.0.0.1"
            rpc_connection = AuthServiceProxy(f"http://{rpc_user}:{rpc_password}@{rpc_address}:{rpc_port}")
            address = rpc_connection.getnewaddress()
            c.execute("INSERT INTO addresses VALUES (?, ?, ?)", (user_id, COINS[coin]['symbol'], address))
            conn.commit()
        c2addresses[COINS[coin]['symbol']] = address
    return web.json_response({COINS[coin]['symbol']: c2addresses[COINS[coin]['symbol']] for coin in COINS})
web_app.router.add_get('/api/topup_addresses', topup_address_handler)

# withdraw page (1% fee, min 10 BOSKA/DGB)
async def withdraw_handler(request):
    session_token = request.cookies.get('session_token')
    if not session_token or session_token not in sessions:
        return web.HTTPFound('/login')
    html_content = open('public/withdraw.html', 'r').read()
    html_content = html_content.replace('{{NAVBAR}}', navbar_html)
    return web.Response(text=html_content, content_type='text/html')
web_app.router.add_get('/withdraw', withdraw_handler)

async def withdraw_options_handler(request):
    # Return supported coins
    options = []
    for coin in COINS:
        options.append(COINS[coin]['symbol'])
    return web.json_response(options)
web_app.router.add_get('/api/withdraw_options', withdraw_options_handler)

async def withdraw_request_handler(request):
    data = await request.json()
    session_token = request.cookies.get('session_token')
    if not session_token or session_token not in sessions:
        return web.json_response({'error': 'Unauthorized'}, status=401)

    user_id = sessions[session_token]
    coin = data.get('coin')
    amount = data.get('amount')
    to_address = data.get('to_address')

    if coin not in [COINS[c]['symbol'] for c in COINS]:
        return web.json_response({'error': 'Unsupported coin'}, status=400)

    if amount < 0.2:
        return web.json_response({'error': 'Invalid amount'}, status=400)

    # Check balance
    c.execute("SELECT amount FROM balances WHERE user_id=? AND coin=?", (user_id, coin))
    row = c.fetchone()
    balance = row[0] if row else 0.0

    total_deduction = amount

    if balance < total_deduction:
        return web.json_response({'error': 'Insufficient balance'}, status=400)

    rpc_user = COINS[coin]['rpc_user']
    rpc_password = COINS[coin]['rpc_password']
    rpc_port = COINS[coin]['rpc_port']
    rpc_address = "127.0.0.1"
    rpc_connection = AuthServiceProxy(f"http://{rpc_user}:{rpc_password}@{rpc_address}:{rpc_port}")
    try:
        wallet_balance = rpc_connection.getbalance()
    except JSONRPCException as e:
        print(f"Error checking wallet balance for {coin}: {e}")
        return web.json_response({'error': 'Withdrawal failed (not enough in host wallet)'}, status=500)
    if wallet_balance < amount * 0.99:  # considering 1% fee
        return web.json_response({'error': 'Withdrawal failed (not enough in host wallet)'}, status=500)

    # Process withdrawal
    new_balance = balance - total_deduction
    c.execute("UPDATE balances SET amount=? WHERE user_id=? AND coin=?", (new_balance, user_id, coin))
    conn.commit()

    # Send the coins using RPC (- 1% fee)
    rpc_connection = AuthServiceProxy(f"http://{rpc_user}:{rpc_password}@{rpc_address}:{rpc_port}")
    try:
        txid = rpc_connection.sendtoaddress(to_address, amount * 0.99)  # 1% fee
        print(f"Processed withdrawal for user {user_id}: {amount} {coin} to {to_address}, txid: {txid}")
    except JSONRPCException as e:
        print(f"Error processing withdrawal for user {user_id}: {e}")
        return web.json_response({'error': 'Withdrawal failed'}, status=500)

    return web.json_response({'status': 'withdrawal_requested', 'new_balance': new_balance, 'transaction_id': txid})

web_app.router.add_post('/api/withdraw_request', withdraw_request_handler)

# Trading page

async def trade_handler(request):
    session_token = request.cookies.get('session_token')
    if not session_token or session_token not in sessions:
        return web.HTTPFound('/login')
    
    html_content = open('public/trade.html', 'r').read()
    html_content = html_content.replace('{{NAVBAR}}', navbar_html)
    return web.Response(text=html_content, content_type='text/html')

web_app.router.add_get('/trade', trade_handler)

async def trade_options_handler(request):
    # Return supported trading pairs (BOSKA/DGB and vice versa)
    options = []
    for coin in COINS:
        options.append(COINS[coin]['symbol'])
    return web.json_response(options)
web_app.router.add_get('/api/trade_options', trade_options_handler)

async def trade_request_handler(request):
    data = await request.json()
    session_token = request.cookies.get('session_token')
    if not session_token or session_token not in sessions:
        return web.json_response({'error': 'Unauthorized'}, status=401)

    user_id = sessions[session_token]
    from_currency = data.get('source_currency')
    to_currency = data.get('target_currency')
    amount = data.get('amount')

    if from_currency == to_currency:
        return web.json_response({'error': 'From and to currencies must be different'}, status=400)

    if from_currency not in [COINS[c]['symbol'] for c in COINS] or to_currency not in [COINS[c]['symbol'] for c in COINS]:
        return web.json_response({'error': 'Unsupported currency'}, status=400)

    if amount < COINS.get(from_currency, {}).get('min_trade_amount', 0):
        return web.json_response({'error': 'Invalid amount'}, status=400)
    if amount > COINS.get(from_currency, {}).get('max_trade_amount', 1e9):
        return web.json_response({'error': 'Amount exceeds maximum limit'}, status=400)

    # Check balance
    c.execute("SELECT amount FROM balances WHERE user_id=? AND coin=?", (user_id, from_currency))
    row = c.fetchone()
    balance = row[0] if row else 0.0

    if balance < amount:
        return web.json_response({'error': 'Insufficient balance'}, status=400)

    # Calculate price
    if from_currency == 'DGB':
        price = dgb_price / calculate_coin_price(to_currency)
    elif to_currency == 'DGB':
        price = calculate_coin_price(from_currency) / dgb_price
    else:
        price = calculate_coin_price(from_currency) / calculate_coin_price(to_currency)

    received_amount = amount * price

    # Update balances
    new_from_balance = balance - amount
    c.execute("UPDATE balances SET amount=? WHERE user_id=? AND coin=?", (new_from_balance, user_id, from_currency))

    c.execute("SELECT amount FROM balances WHERE user_id=? AND coin=?", (user_id, to_currency))
    row = c.fetchone()
    to_balance = row[0] if row else 0.0
    new_to_balance = to_balance + received_amount
    if row:
        c.execute("UPDATE balances SET amount=? WHERE user_id=? AND coin=?", (new_to_balance, user_id, to_currency))
    else:
        c.execute("INSERT INTO balances VALUES (?, ?, ?)", (user_id, to_currency, received_amount))

    conn.commit()

    # Log trade
    timestamp = str(int(time.time()))
    log_trade(timestamp, price, amount, from_currency, to_currency, None, None)

    return web.json_response({'ok': 1, 'new_from_balance': new_from_balance, 'new_to_balance': new_to_balance})
web_app.router.add_post('/api/trade', trade_request_handler)

async def price_estimate_handler(request):
    from_currency = request.query.get('source_currency')
    to_currency = request.query.get('target_currency')
    amount = float(request.query.get('amount', 0))

    if from_currency == to_currency:
        return web.json_response({'error': 'From and to currencies must be different'}, status=400)

    if from_currency not in [COINS[c]['symbol'] for c in COINS] or to_currency not in [COINS[c]['symbol'] for c in COINS]:
        return web.json_response({'error': 'Unsupported currency'}, status=400)

    if amount <= 0:
        return web.json_response({'error': 'Invalid amount'}, status=400)

    # Calculate price
    if from_currency == 'DGB':
        price = dgb_price / calculate_coin_price(to_currency)
    elif to_currency == 'DGB':
        price = calculate_coin_price(from_currency) / dgb_price
    else:
        price = calculate_coin_price(from_currency) / calculate_coin_price(to_currency)

    estimated_amount = amount * price

    return web.json_response({'estimated_amount': estimated_amount})
web_app.router.add_get('/api/price_estimate', price_estimate_handler)

# List trades
async def list_trades_handler(request):
    # session_token = request.cookies.get('session_token')
    # if not session_token or session_token not in sessions:
    #     return web.json_response({'error': 'Unauthorized'}, status=401)

    # user_id = sessions[session_token]
    c.execute("SELECT * FROM trades ORDER BY timestamp DESC LIMIT 100")
    rows = c.fetchall()
    trades = []
    for row in rows:
        trades.append({
            'timestamp': row[0],
            'price': row[1],
            'amount': row[2],
            'from_currency': row[3],
            'to_currency': row[4],
            'from_address': row[5],
            'to_address': row[6]
        })
    return web.json_response({'trades': trades})
web_app.router.add_get('/api/trades', list_trades_handler)

# Static file handler

async def popper_handler(request):
    with open('public/popper.js', 'rb') as f:
        content = f.read()
    return web.Response(body=content, content_type='application/javascript')
web_app.router.add_get('/popper.js', popper_handler)

async def static_handler(request):
    path = request.match_info.get('path', 'index.html')
    try:
        with open(f'public/{path}', 'rb') as f:
            content = f.read()
        if path.endswith('.css'):
            return web.Response(body=content, content_type='text/css')
        elif path.endswith('.js'):
            return web.Response(body=content, content_type='application/javascript')
        elif path.endswith('.png'):
            return web.Response(body=content, content_type='image/png')
        else:
            return web.Response(body=content, content_type='application/octet-stream')
    except FileNotFoundError:
        return web.Response(status=404, text='File not found')
web_app.router.add_get('/static/{path:.*}', static_handler)

# /api/pending_deposits
async def pending_deposits_handler(request):
    session_token = request.cookies.get('session_token')
    if not session_token or session_token not in sessions:
        return web.json_response({'error': 'Unauthorized'}, status=401)

    user_id = sessions[session_token]
    c.execute("SELECT * FROM pending_deposits WHERE user_id=?", (user_id,))
    rows = c.fetchall()
    pending_deposits = []
    for row in rows:
        pending_deposits.append({
            'coin': row[1],
            'amount': row[2],
            'txid': row[3],
            'confirmations': row[4],
            'required_confirmations': 6,
            'tx_url': COINS.get(row[1], {}).get('explorer_tx', '') + row[3]
        })
    pending_deposits.reverse()
    return web.json_response({'pending_deposits': pending_deposits})
web_app.router.add_get('/api/pending_deposits', pending_deposits_handler)

# /logout
async def logout_handler(request):
    session_token = request.cookies.get('session_token')
    if session_token and session_token in sessions:
        del sessions[session_token]
    response = web.HTTPFound('/login')
    response.del_cookie('session_token')
    return response
web_app.router.add_get('/logout', logout_handler)

# /addcoin page
async def addcoin_handler(request):
    html_content = open('public/addcoin.html', 'r').read()
    html_content = html_content.replace('{{NAVBAR}}', navbar_html)
    return web.Response(text=html_content, content_type='text/html')
web_app.router.add_get('/addcoin', addcoin_handler)

# Periodically check for deposits (top-ups)
def check_deposits():
    for coin in COINS:
        print ("DEBUG: Checking deposits for", COINS[coin]['symbol'])
        rpc_user = COINS[coin]['rpc_user']
        rpc_password = COINS[coin]['rpc_password']
        rpc_port = COINS[coin]['rpc_port']
        rpc_address = "127.0.0.1"
        rpc_connection = AuthServiceProxy(f"http://{rpc_user}:{rpc_password}@{rpc_address}:{rpc_port}")
        c = conn.cursor()
        c.execute("SELECT user_id, address FROM addresses WHERE coin=?", (COINS[coin]['symbol'],))
        rows = c.fetchall()
        for row in rows:
            print ("DEBUG: Checking deposits for user/address", row)
            user_id, address = row
            try:
                transactions = rpc_connection.listtransactions("*", 100)
                for tx in transactions:
                    print ("DEBUG: Examining transaction", tx)
                    num_confirmations = tx.get('confirmations', 0)
                    if tx['address'] == address and tx['category'] == 'receive' and not tx.get('processed', False):
                        if num_confirmations < 6:
                            c.execute("SELECT * FROM pending_deposits WHERE txid=?", (tx['txid'],))
                            if c.fetchone():
                                c.execute("UPDATE pending_deposits SET confirmations=? WHERE txid=?", (num_confirmations, tx['txid']))
                            else:
                                c.execute("INSERT INTO pending_deposits VALUES (?, ?, ?, ?, ?)",
                                          (user_id, COINS[coin]['symbol'], float(tx['amount']), tx['txid'], num_confirmations))
                            conn.commit()
                            continue  # Skip unconfirmed transactions
                        print ("DEBUG: Found deposit transaction", tx)
                        amount = int(tx['amount'] * decimal.Decimal(1e8)) / 1e8  # Convert to float with 8 decimal places
                        txid = tx['txid']
                        timestamp = tx['time']
                        # Check if this transaction has already been processed
                        c.execute("SELECT * FROM deposits WHERE txid=?", (txid,))
                        if c.fetchone():
                            continue  # Already processed
                        c.execute("INSERT INTO deposits VALUES (?, ?, ?, ?, ?)",
                                    (timestamp, user_id, COINS[coin]['symbol'], amount, txid))
                        
                        c.execute("SELECT * FROM balances WHERE user_id=? AND coin=?", (user_id, COINS[coin]['symbol']))
                        if not c.fetchone():
                            c.execute("INSERT INTO balances VALUES (?, ?, ?)", (user_id, COINS[coin]['symbol'], 0.0))
                        # Update balance
                        c.execute("UPDATE balances SET amount = amount + ? WHERE user_id=? AND coin=?",
                                  (amount, user_id, COINS[coin]['symbol']))
                        # c.execute("UPDATE trades SET processed=1 WHERE from_address=? AND to_address=? AND timestamp=?",
                        #           (address, None, timestamp))
                        # update pending_deposits to processed
                        c.execute("UPDATE pending_deposits SET confirmations=6 WHERE txid=?", (txid,))
                        conn.commit()
            except Exception as e:
                print(f"Error checking deposits for {COINS[coin]['symbol']}: {e}")


def deposit_checker_thread():
    while True:
        check_deposits()
        time.sleep(10)  # Check every 10 seconds

deposit_thread = threading.Thread(target=deposit_checker_thread, daemon=True)
deposit_thread.start()

web.run_app(web_app, host='0.0.0.0', port=8080)
