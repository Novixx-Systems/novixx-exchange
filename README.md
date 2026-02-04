# Novixx Exchange - Open Source Crypto Trading Platform (CEX)
Novixx Exchange is an open-source centralized cryptocurrency exchange platform built with Python and SQLite.

## Features
- User registration and authentication
- Cryptocurrency trading (buy/sell)
- Wallet management
- Withdraw/deposit functionality

## Configuration
Use coins.json to configure supported cryptocurrencies and their RPC settings.

```json
{
    "BOSKA": {
        "name": "BoskaCoin",
        "symbol": "BOSKA",
        "algorithm": "Scrypt",
        "website": "https://boskacoin.org",
        "explorer_tx": "https://explorer.boskacoin.org/tx/",
        "rpc_port": 19918,
        "rpc_user": "user",
        "rpc_password": "pass",
        "default_price_usdt": 0.0005,
        "min_trade_amount": 1,
        "max_trade_amount": 1000
    },
    "DGB": {
        "name": "DigiByte",
        "symbol": "DGB",
        "algorithm": "Scrypt",
        "website": "https://digibyte.org",
        "explorer_tx": "https://digiexplorer.info/tx/",
        "rpc_port": 14022,
        "rpc_user": "user",
        "rpc_password": "pass",
        "min_trade_amount": 1,
        "max_trade_amount": 1000
    }
}
```

## Why SQLite?
Because it's currently a lightweight project and SQLite is easy to set up without requiring a separate database server, but we will migrate to MySQL soon.

YES I KNOW I WAS JOKING ABOUT THIS IN HCC DISCORD BUT IT IS JUST WAY EASIER TO SET UP

## Why is the code messy?
This was a quick prototype to make a working exchange platform. We plan to refactor and clean up the code in future commits.

# Inspirations
[HCC](https://hashcash-pow-faucet.dynv6.net/) was an inspiration for this project

[KlingEx](https://klingex.io/) was also an inspiration for this project
