# tools.py
import random
import datetime

def get_apple_exec_info():

    print("get_apple_exec_info called")
    # your existing logic here...
    result = {
        "CEO": "Tim Cook",
        "Employees": 164000,
        "Revenue": "394.3B"
    }
    print(f"get_apple_exec_info result: {result}")
    return result

def get_apple_stock_price():
    return {
        "symbol": "AAPL",
        "price": 235.42,
        "currency": "USD",
        "as_of": str(datetime.date.today())
    }

def get_apple_historical_price():
    return {
        "symbol": "AAPL",
        "historical_prices": {
            "2023-01-01": 145.32,
            "2023-06-01": 175.65,
            "2024-01-01": 200.78
        }
    }

def get_random_noise():
    return {"random": random.randint(0, 9999)}
