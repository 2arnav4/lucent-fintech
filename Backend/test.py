import requests

BASE_URL = "http://127.0.0.1:5000"

def safe_print_response(resp, description):
    print(f"--- {description} ---")
    print(f"Status Code: {resp.status_code}")
    try:
        print("Response JSON:", resp.json())
    except Exception as e:
        print(f"JSON decode failed: {e}")
        print("Response Text:", resp.text)
    print("")

def test_signup():
    url = f"{BASE_URL}/signup"
    data = {"email": "test@example.com", "password": "password123"}
    resp = requests.post(url, json=data)
    safe_print_response(resp, "Signup")
    return resp.json().get("token") if resp.status_code == 200 else None

def test_login():
    url = f"{BASE_URL}/login"
    data = {"email": "test@example.com", "password": "password123"}
    resp = requests.post(url, json=data)
    safe_print_response(resp, "Login")
    return resp.json().get("token") if resp.status_code == 200 else None

def test_market_news():
    url = f"{BASE_URL}/market-news"
    resp = requests.get(url)
    safe_print_response(resp, "Market News")
    if resp.status_code == 200:
        for i, article in enumerate(resp.json(), 1):
            print(f"{i}. Category: {article.get('category')}, Headline: {article.get('headline')}, Source: {article.get('source')}")
    print("")

def test_ai_insights(token):
    url = f"{BASE_URL}/ai-insights"
    headers = {"Authorization": f"Bearer {token}"}
    data = {"query": "How can I save money?"}
    resp = requests.post(url, headers=headers, json=data)
    safe_print_response(resp, "AI Insights")

def test_stock_trends():
    url = f"{BASE_URL}/trends/stocks"
    params = {"symbols": "AAPL,GOOG", "date_from": "2023-01-01", "date_to": "2023-03-01"}
    resp = requests.get(url, params=params)
    safe_print_response(resp, "Stock Trends")

def test_crypto_rates():
    url = f"{BASE_URL}/trends/crypto"
    resp = requests.get(url)
    safe_print_response(resp, "Crypto Rates")

def test_circle_flow(token):
    headers = {"Authorization": f"Bearer {token}"}

    # Create circle
    url = f"{BASE_URL}/circles"
    data = {
        "name": "Friends Group",
        "member_ids": []  # You can add other user IDs here if available
    }
    resp = requests.post(url, headers=headers, json=data)
    safe_print_response(resp, "Create Circle")
    if resp.status_code != 200:
        return
    circle_id = resp.json().get("circle_id")

    # List circles
    url = f"{BASE_URL}/circles"
    resp = requests.get(url, headers=headers)
    safe_print_response(resp, "List Circles")

    # Add expense
    url = f"{BASE_URL}/circles/{circle_id}/expenses"
    data = {"amount": 1200, "description": "Dinner at restaurant", "date": "2025-01-01"}
    resp = requests.post(url, headers=headers, json=data)
    safe_print_response(resp, "Add Expense")
    if resp.status_code != 200:
        return
    expense_id = resp.json().get("expense_id")

    # List expenses
    url = f"{BASE_URL}/circles/{circle_id}/expenses"
    resp = requests.get(url, headers=headers)
    safe_print_response(resp, "List Expenses")

    # Remove expense
    url = f"{BASE_URL}/circles/{circle_id}/expenses/{expense_id}"
    resp = requests.delete(url, headers=headers)
    safe_print_response(resp, "Remove Expense")

if __name__ == "__main__":
    print("Testing Signup and Login:")
    token = test_signup()
    if not token:
        token = test_login()

    if token:
        test_market_news()
        test_ai_insights(token)
        test_stock_trends()
        test_crypto_rates()
        test_circle_flow(token)
    else:
        print("Failed to acquire auth token; skipping further tests.")
