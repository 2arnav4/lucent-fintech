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
    data = {
        "email": "test@example.com",
        "password": "password123"
    }
    resp = requests.post(url, json=data)
    safe_print_response(resp, "Signup")
    return resp.json().get("token") if resp.status_code == 200 else None

def test_login():
    url = f"{BASE_URL}/login"
    data = {
        "email": "test@example.com",
        "password": "password123"
    }
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
    headers = {
        "Authorization": f"Bearer {token}"
    }
    data = {
        "query": "How can I save money?"
    }
    resp = requests.post(url, headers=headers, json=data)
    safe_print_response(resp, "AI Insights")

if __name__ == "__main__":
    print("Testing Signup and Login:")
    token = test_signup()
    if not token:
        token = test_login()

    if token:
        test_market_news()
        test_ai_insights(token)
    else:
        print("Failed to acquire auth token; skipping AI insights test.")
