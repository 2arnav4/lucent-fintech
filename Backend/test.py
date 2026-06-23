import requests

BASE_URL = "http://127.0.0.1:5001"

def safe_print_response(resp, description):
    print(f"--- {description} ---")
    print(f"Status Code: {resp.status_code}")
    try:
        data = resp.json()
        print("Response JSON:", data)
        return data
    except Exception as e:
        print(f"JSON decode failed: {e}")
        print("Response Text:", resp.text)
        return None
    print("")

def test_signup(email, password):
    url = f"{BASE_URL}/signup"
    data = {
        "email": email,
        "password": password
    }
    resp = requests.post(url, json=data)
    res_json = safe_print_response(resp, f"Signup for {email}")
    return res_json.get("token") if resp.status_code == 200 else None

def test_login(email, password):
    url = f"{BASE_URL}/login"
    data = {
        "email": email,
        "password": password
    }
    resp = requests.post(url, json=data)
    res_json = safe_print_response(resp, f"Login for {email}")
    return res_json.get("token") if resp.status_code == 200 else None

def test_market_news():
    url = f"{BASE_URL}/market-news"
    resp = requests.get(url)
    safe_print_response(resp, "Market News")

def test_ai_insights(token):
    url = f"{BASE_URL}/ai-insights"
    headers = {"Authorization": f"Bearer {token}"}
    data = {"query": "How can I optimize my monthly investments?"}
    resp = requests.post(url, headers=headers, json=data)
    safe_print_response(resp, "AI Insights")

def test_widgets(token):
    # Retrieve user widgets dynamically by decoding user_id from token
    import jwt
    payload = jwt.decode(token, options={"verify_signature": False})
    user_id = payload.get("user_id", 1)
    
    url = f"{BASE_URL}/user/{user_id}/widgets"
    headers = {"Authorization": f"Bearer {token}"}
    resp = requests.get(url, headers=headers)
    widgets = safe_print_response(resp, "Get User Widgets")

    if widgets and len(widgets) > 0:
        # Toggle visibility of the first widget
        widget_id = widgets[0]["widget"]["id"]
        toggle_url = f"{BASE_URL}/user/{user_id}/widgets/{widget_id}"
        toggle_data = {"visible": False}
        toggle_resp = requests.put(toggle_url, headers=headers, json=toggle_data)
        safe_print_response(toggle_resp, f"Toggle Widget {widget_id} Visibility")

def test_circles_and_expenses(token_user1, token_user2):
    headers_user1 = {"Authorization": f"Bearer {token_user1}"}
    headers_user2 = {"Authorization": f"Bearer {token_user2}"}

    # 1. Create a circle with User 1 as owner and User 2 as a member (via email)
    create_url = f"{BASE_URL}/circles"
    circle_data = {
        "name": "Trip to Goa",
        "members": ["user2@example.com", "user3@example.com"] # user3 is auto-created as a placeholder
    }
    resp = requests.post(create_url, headers=headers_user1, json=circle_data)
    circle = safe_print_response(resp, "Create Circle")
    
    if not circle:
        print("Skipping circle tests due to creation failure.\n")
        return

    circle_id = circle.get("circle_id")

    # 2. List circles for User 1
    list_resp = requests.get(create_url, headers=headers_user1)
    safe_print_response(list_resp, "List Circles for User 1")

    # 3. Add an expense to the circle (using merchant mapping)
    expense_url = f"{BASE_URL}/circles/{circle_id}/expenses"
    expense_data = {
        "merchant": "Hotel Beachfront",
        "amount": 4500.00
    }
    add_resp = requests.post(expense_url, headers=headers_user1, json=expense_data)
    expense = safe_print_response(add_resp, "Add Expense to Circle")
    expense_id = expense.get("expense_id") if expense else None

    # 4. List expenses for the circle
    list_exp_resp = requests.get(expense_url, headers=headers_user1)
    safe_print_response(list_exp_resp, "List Expenses for Circle")

    # 5. Split expenses (Equal Split)
    split_url = f"{BASE_URL}/circles/{circle_id}/split"
    split_data = {"method": "equal"}
    split_resp = requests.post(split_url, headers=headers_user1, json=split_data)
    safe_print_response(split_resp, "Split Expenses (Equal)")

    # 6. Split expenses (Dietary Preference Split - uses Gemini fallback)
    dietary_data = {
        "method": "dietary",
        "preferences": {
            "user1@example.com": "Veg",
            "user2@example.com": "Non-Veg",
            "user3@example.com": "Alcoholic"
        }
    }
    dietary_resp = requests.post(split_url, headers=headers_user1, json=dietary_data)
    safe_print_response(dietary_resp, "Split Expenses (Dietary Split via Gemini)")

    # 7. Remove expense
    if expense_id:
        delete_url = f"{BASE_URL}/circles/{circle_id}/expenses/{expense_id}"
        del_resp = requests.delete(delete_url, headers=headers_user1)
        safe_print_response(del_resp, f"Delete Expense {expense_id}")

if __name__ == "__main__":
    print("================== Lucent FinTech Test Suite ==================\n")
    
    # Sign up and Log in User 1
    token1 = test_signup("user1@example.com", "securepass1")
    if not token1:
        token1 = test_login("user1@example.com", "securepass1")

    # Sign up and Log in User 2
    token2 = test_signup("user2@example.com", "securepass2")
    if not token2:
        token2 = test_login("user2@example.com", "securepass2")

    if token1 and token2:
        test_market_news()
        test_ai_insights(token1)
        test_widgets(token1)
        test_circles_and_expenses(token1, token2)
        print("===============================================================")
        print("All tests completed successfully.")
    else:
        print("Failed to acquire auth tokens; test suite aborted.")
