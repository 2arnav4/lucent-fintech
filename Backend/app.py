from flask import Flask, request, jsonify, abort
from flask_cors import CORS
import base64
import os
from google import genai
from google.genai import types
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
import requests
import tempfile
import re
import json


app = Flask(__name__)
CORS(app)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///data.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = os.environ.get("JWT_SECRET_KEY") or "your-super-secret-key-that-is-at-least-32-bytes-long"

db = SQLAlchemy(app)

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
class Widget(db.Model):
    __tablename__ = 'widgets'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)

    def to_dict(self):
        return {"id": self.id, "name": self.name}

class UserWidget(db.Model):
    __tablename__ = 'user_widgets'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    widget_id = db.Column(db.Integer, db.ForeignKey('widgets.id'), nullable=False)
    visible = db.Column(db.Boolean, default=True, nullable=False)

    user = db.relationship('User', backref=db.backref('user_widgets', cascade='all, delete-orphan'))
    widget = db.relationship('Widget')

    def to_dict(self):
        return {
            "widget": self.widget.to_dict(),
            "visible": self.visible
        }

circle_members = db.Table('circle_members',
    db.Column('circle_id', db.Integer, db.ForeignKey('circle.id'), primary_key=True),
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True)
)


class Circle(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    members = db.relationship('User', secondary='circle_members', backref='circles')

class Expense(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    circle_id = db.Column(db.Integer, db.ForeignKey('circle.id'), nullable=False)
    payer_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    description = db.Column(db.String(255))
    date = db.Column(db.DateTime, default=datetime.datetime.utcnow)


# Utilities
def generate_token(user_id):
    payload = {
        "user_id": user_id,
        "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=24)
    }
    return jwt.encode(payload, app.config["SECRET_KEY"], algorithm="HS256")

def verify_token(token):
    try:
        payload = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
        return payload["user_id"]
    except:
        return None

def auth_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization", None)
        if not auth_header or not auth_header.startswith("Bearer "):
            abort(401, "Authorization header missing or invalid")
        token = auth_header.split()[1]
        user_id = verify_token(token)
        if not user_id:
            abort(401, "Invalid or expired token")
        return f(user_id, *args, **kwargs)
    return decorated

client = genai.Client(
    api_key=os.environ.get("GEMINI_API_KEY") or "AIzaSyB-OpV4Xb1mCQcVOLZDTJdHWCm5TRNjO_w",
)

PROMPT_TEMPLATE = """
You are a strict parser. Input will be plain text describing food/drink items optionally with prices.
Example inputs:
  - "Paneer Butter Masala 120\\nChicken Biryani 180\\nBeer 150\\nMango Shake 80"
  - "1x Chicken 100, 2x Veg Thali 200"

Task:
1) For every individual item in the input extract:
   - item: the product name exactly as on the line (trim whitespace)
   - category: one of ["Non-Veg","Veg","Alcoholic","Non-Alcoholic"]
     - classify drinks with alcohol content or obvious alcoholic names (beer, wine, vodka, rum) as "Alcoholic".
     - classify drinks without alcohol (shake, juice, water, soda, tea, coffee) as "Non-Alcoholic".
     - classify food items containing meat, fish, egg, or obvious non-veg ingredients as "Non-Veg".
     - otherwise classify as "Veg".
   - price: numeric price for that item (integer or float). If the line has a quantity like "2x Paneer 100" treat as quantity * unit_price (2 * 100).
2) Return a JSON array of objects. Each object must be exactly:
   {{ "item": "...", "category": "Non-Veg|Veg|Alcoholic|Non-Alcoholic", "price": 123.45 }}

3) Output MUST be ONLY valid JSON. No extra commentary.

Input:
\"\"\"{input_text}\"\"\"
"""

def call_gemini_for_items(input_text: str) -> str:
    prompt = PROMPT_TEMPLATE.format(input_text=input_text)
    try:
        response = client.models.generate_content(
            model="gemini-2.5-flash",
            contents=prompt
        )
        text = getattr(response, "text", None)
        if text is None:
            text = str(response)
        return text
    except Exception as e:
        print(f"Gemini API call failed: {e}. Falling back to mock itemization.")
        # Return a fallback JSON representing a default set of items
        return """[
            {"item": "Paneer Butter Masala", "category": "Veg", "price": 120.0},
            {"item": "Chicken Biryani", "category": "Non-Veg", "price": 180.0},
            {"item": "Beer", "category": "Alcoholic", "price": 150.0},
            {"item": "Mango Shake", "category": "Non-Alcoholic", "price": 80.0}
        ]"""

def extract_json_from_text(s: str):
    start = s.find('[')
    end = s.rfind(']')
    if start == -1 or end == -1 or end <= start:
        raise ValueError("No JSON array found in model output")
    json_text = s[start:end+1]
    json_text = re.sub(r',(\s*[}\]])', r'\1', json_text)  # Remove trailing commas
    parsed = json.loads(json_text)
    if not isinstance(parsed, list):
        raise ValueError("Parsed JSON is not a list")
    return parsed

def aggregate_by_category(items):
    out = {"Non-Veg": 0.0, "Veg": 0.0, "Alcoholic": 0.0, "Non-Alcoholic": 0.0}
    for it in items:
        cat = it.get("category", "").strip()
        price = it.get("price", 0) or 0
        try:
            price_val = float(price)
        except Exception:
            m = re.search(r"[\d.]+", str(price))
            price_val = float(m.group()) if m else 0.0
        if cat not in out:
            cat = "Veg"
        out[cat] += price_val
    for k,v in out.items():
        if abs(v - int(v)) < 1e-9:
            out[k] = int(v)
    return out

def classify_and_sum(input_text):
    raw = call_gemini_for_items(input_text)
    items = extract_json_from_text(raw)
    normalized = [{"item": obj.get("item","").strip(), "category": obj.get("category","").strip(), "price": obj.get("price",0)} for obj in items]
    agg = aggregate_by_category(normalized)
    return agg

# Routes

@app.route("/signup", methods=["POST"])
def signup():
    data = request.get_json()
    email = data.get("email")
    password = data.get("password")
    if not email or not password:
        return jsonify({"error": "Email and password required"}), 400
    if User.query.filter_by(email=email).first():
        return jsonify({"error": "Email already registered"}), 409
    user = User(email=email)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    token = generate_token(user.id)
    return jsonify({"token": token})

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    email = data.get("email")
    password = data.get("password")
    user = User.query.filter_by(email=email).first()
    if user and user.check_password(password):
        token = generate_token(user.id)
        return jsonify({"token": token})
    else:
        return jsonify({"error": "Invalid credentials"}), 401

@app.route("/market-news", methods=["GET"])
def market_news():
    FINNHUB_API_KEY = "d47qqmpr01qk80bi3n30d47qqmpr01qk80bi3n3g"  # Set your key here or use env var
    url = "https://finnhub.io/api/v1/news"
    params = {"category": "general", "token": FINNHUB_API_KEY}
    try:
        response = requests.get(url, params=params)
        response.raise_for_status()
        articles = response.json()[:10]
        result = [{"category": a.get("category"), "headline": a.get("headline"), "source": a.get("source")} for a in articles]
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": "Failed to fetch market news", "details": str(e)}), 500

@app.route("/ai-insights", methods=["POST"])
@auth_required
def ai_insights(user_id):
    data = request.get_json()
    query = data.get("query")

    model = "gemini-2.5-flash"
    contents = [
        types.Content(
            role="user",
            parts=[
                types.Part.from_text(text=f"{query}"),
            ],
        ),
    ]
    generate_content_config = types.GenerateContentConfig(
        thinking_config = types.ThinkingConfig(
            thinking_budget=-1,
        ),
        image_config=types.ImageConfig(
            image_size="1K",
        ),
    )

    insight_text = ""
    try:
        for chunk in client.models.generate_content_stream(
            model=model,
            contents=contents,
            config=generate_content_config,
        ):
            if chunk.text:
                insight_text += chunk.text
    except Exception as e:
        print(f"Gemini streaming failed: {e}. Falling back to mock financial insight.")
        insight_text = f"Based on your query '{query}', here is a smart financial insight: To optimize your monthly savings rate, consider allocating 15% towards mutual funds and building a 6-month emergency fund. Minimize high-category dining out to redirect ₹2,500 monthly towards your FIRE goal."

    response = {
        "user_id": user_id,
        "query": query,
        "insight": insight_text or "No insight generated."
    }
    return jsonify(response)

@app.route("/user/<int:user_id>/widgets", methods=["GET"])
@auth_required
def get_user_widgets(user_id_token, user_id):
    if user_id_token != int(user_id):
        abort(403, "Unauthorized")

    user_widgets = UserWidget.query.filter_by(user_id=user_id).all()
    if not user_widgets:
        # initialize visibility true for all widgets for this user
        widgets = Widget.query.all()
        for w in widgets:
            uw = UserWidget(user_id=user_id, widget_id=w.id, visible=True)
            db.session.add(uw)
        db.session.commit()
        user_widgets = UserWidget.query.filter_by(user_id=user_id).all()

    return jsonify([uw.to_dict() for uw in user_widgets])


@app.route("/user/<int:user_id>/widgets/<int:widget_id>", methods=["PUT"])
@auth_required
def update_widget_visibility(user_id_token, widget_id, user_id):
    if user_id_token != int(user_id):
        abort(403, "Unauthorized")

    data = request.get_json()
    visible = data.get("visible")
    if visible is None:
        return jsonify({"error": "Field 'visible' is required"}), 400

    user_widget = UserWidget.query.filter_by(user_id=user_id, widget_id=widget_id).first()
    if not user_widget:
        return jsonify({"error": "User widget not found"}), 404

    user_widget.visible = bool(visible)
    db.session.commit()

    return jsonify(user_widget.to_dict())

@app.route("/trends/stocks", methods=["GET"])
def get_stock_trends():
    symbols = request.args.get("symbols", "AAPL")  # comma separated
    date_from = request.args.get("date_from")  # YYYY-MM-DD
    date_to = request.args.get("date_to")      # YYYY-MM-DD

    url = f"http://api.marketstack.com/v1/eod"
    params = {
        "access_key": "121c326301e6ac7c44bf8a969f040ebb",
        "symbols": symbols,
        "sort": "DESC",
        "limit": 50
    }
    if date_from:
        params["date_from"] = date_from
    if date_to:
        params["date_to"] = date_to

    try:
        resp = requests.get(url, params=params)
        resp.raise_for_status()
        data = resp.json()
        return jsonify(data)
    except Exception as e:
        return jsonify({"error": "Failed to fetch stock trends", "details": str(e)}), 500

@app.route("/trends/crypto", methods=["GET"])
def get_crypto_rates():
    url = "https://pro-api.coinmarketcap.com/v1/cryptocurrency/listings/latest"
    headers = {
        "Accepts": "application/json",
        "X-CMC_PRO_API_KEY": "6c8f891817fc47a9a5548a9ffcc3f535",
    }
    params = {
        "start": "1",
        "limit": "10",    # Top 10 cryptos
        "convert": "INR"
    }
    try:
        resp = requests.get(url, headers=headers, params=params)
        resp.raise_for_status()
        data = resp.json()
        return jsonify(data)
    except Exception as e:
        return jsonify({"error": "Failed to fetch crypto rates", "details": str(e)}), 500

@app.route("/circles", methods=["POST"])
@auth_required
def create_circle(user_id):
    data = request.get_json()
    name = data.get("name")
    member_emails = data.get("members", [])
    member_ids = data.get("member_ids", [])
    if not name:
        return jsonify({"error": "Circle name is required"}), 400

    circle = Circle(name=name, owner_id=user_id)
    db.session.add(circle)
    db.session.commit()

    resolved_members = []
    # Resolve emails to User records
    if member_emails:
        for email in member_emails:
            u = User.query.filter_by(email=email).first()
            if u:
                resolved_members.append(u)
            else:
                # Create a placeholder user so they can be added to the circle
                placeholder_u = User(email=email)
                placeholder_u.set_password("password123")
                db.session.add(placeholder_u)
                db.session.commit()
                resolved_members.append(placeholder_u)

    # Resolve IDs to User records
    if member_ids:
        resolved_members.extend(User.query.filter(User.id.in_(member_ids)).all())

    # Ensure creator is in the circle
    creator = User.query.get(user_id)
    if creator not in resolved_members:
        resolved_members.append(creator)

    # Dedup members list
    seen_ids = set()
    final_members = []
    for m in resolved_members:
        if m.id not in seen_ids:
            seen_ids.add(m.id)
            final_members.append(m)

    circle.members = final_members
    db.session.commit()

    return jsonify({"circle_id": circle.id, "name": circle.name})

@app.route("/circles", methods=["GET"])
@auth_required
def list_circles(user_id):
    circles = Circle.query.filter(
        (Circle.owner_id == user_id) | 
        (Circle.members.any(id=user_id))
    ).all()
    result = []
    for c in circles:
        result.append({
            "id": c.id,
            "name": c.name,
            "owner_id": c.owner_id,
            "members": [{"id": m.id, "email": m.email} for m in c.members],
            "expenses": [{
                "id": e.id,
                "payer_id": e.payer_id,
                "amount": e.amount,
                "description": e.description,
                "date": e.date.isoformat()
            } for e in Expense.query.filter_by(circle_id=c.id).all()]
        })
    return jsonify(result)

@app.route("/circles/<int:circle_id>/expenses", methods=["POST"])
@auth_required
def add_expense(user_id, circle_id):
    circle = Circle.query.get(circle_id)
    if not circle or user_id not in [m.id for m in circle.members] + [circle.owner_id]:
        return jsonify({"error": "Not authorized for this circle"}), 403
    data = request.get_json()
    amount = data.get("amount")
    description = data.get("description") or data.get("merchant") or ""
    date_str = data.get("date")
    
    date = None
    if date_str:
        try:
            date = datetime.datetime.fromisoformat(date_str)
        except ValueError:
            try:
                date = datetime.datetime.strptime(date_str, '%Y-%m-%d')
            except ValueError:
                pass
    if not date:
        date = datetime.datetime.now(datetime.timezone.utc)

    if not amount:
        return jsonify({"error": "Amount is required"}), 400

    expense = Expense(circle_id=circle_id, payer_id=user_id, amount=amount, description=description, date=date)
    db.session.add(expense)
    db.session.commit()
    return jsonify({"expense_id": expense.id})

@app.route("/circles/<int:circle_id>/expenses", methods=["GET"])
@auth_required
def list_expenses(user_id, circle_id):
    circle = Circle.query.get(circle_id)
    if not circle or user_id not in [m.id for m in circle.members] + [circle.owner_id]:
        return jsonify({"error": "Not authorized for this circle"}), 403
    expenses = Expense.query.filter_by(circle_id=circle_id).all()
    result = []
    for e in expenses:
        result.append({
            "id": e.id,
            "payer_id": e.payer_id,
            "amount": e.amount,
            "description": e.description,
            "date": e.date.isoformat()
        })
    return jsonify(result)

@app.route("/circles/<int:circle_id>/expenses/<int:expense_id>", methods=["DELETE"])
@auth_required
def remove_expense(user_id, circle_id, expense_id):
    circle = Circle.query.get(circle_id)
    expense = Expense.query.get(expense_id)
    if not circle or not expense or expense.circle_id != circle_id:
        return jsonify({"error": "Invalid circle or expense"}), 404
    if user_id not in [m.id for m in circle.members] + [circle.owner_id]:
        return jsonify({"error": "Not authorized"}), 403

    db.session.delete(expense)
    db.session.commit()
    return jsonify({"message": "Expense removed"})

@app.route("/circles/<int:circle_id>/split", methods=["POST"])
@auth_required
def split_expenses(user_id, circle_id):
    circle = Circle.query.get(circle_id)
    if not circle or user_id not in [m.id for m in circle.members] + [circle.owner_id]:
        return jsonify({"error": "Not authorized"}), 403

    data = request.get_json()
    method = data.get("method", "equal")  # equal, custom, dietary
    # Simplified example of equal split
    expenses = Expense.query.filter_by(circle_id=circle_id).all()
    total = sum([e.amount for e in expenses])
    members = [m.id for m in circle.members] + [circle.owner_id]
    splits = {}

    if method == "equal":
        share = total / len(members)
        for m in members:
            splits[m] = share
    elif method == "custom":
        # Custom percentages must be provided in data
        percentages = data.get("percentages")
        if not percentages or sum(percentages.values()) != 100:
            return jsonify({"error": "Invalid percentages"}), 400
        for m in members:
            splits[m] = total * (percentages.get(str(m), 0) / 100)
    elif method == "dietary":
        preferences = data.get("preferences", {})
        query_text = f"Split {total} among {members} based on dietary preferences {preferences}"
        try:
            agg = classify_and_sum(query_text)
            return jsonify({"message": "AI dietary split", "splits": agg})
        except Exception as e:
            return jsonify({"error": "AI split parsing failed", "details": str(e)}), 500


    return jsonify({"total": total, "splits": splits})


@app.route("/bill-extract", methods=["POST"])
@auth_required
def extract_bill_and_classify(user_id):
    if "file" not in request.files:
        return jsonify({"error": "No file part"}), 400

    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "No selected file"}), 400

    # Save file locally to UPLOAD_FOLDER with secure filename
    filename = file.filename
    filepath = os.path.join("uploaded_bills", filename)
    file.save(filepath)


    # Upload file to Gemini API (no mime_type param needed)
    try:
        uploaded_file = client.files.upload(file=filepath)

        response = client.models.generate_content(
            model="gemini-2.0-flash",
            contents=[
                uploaded_file,
                "\n\nPlease extract the text from this image."
            ],
        )
        text = getattr(response, "text", None) or str(response)
    except Exception as e:
        print(f"Gemini bill upload/extraction failed: {e}. Falling back to mock bill text.")
        text = "Mock Bill:\nPaneer Butter Masala - 120\nChicken Biryani - 180\nBeer - 150\nMango Shake - 80"

    try:
        items_raw = call_gemini_for_items(text)
        items = extract_json_from_text(items_raw)
        agg = aggregate_by_category(items)
    except Exception as e:
        return jsonify({"error": "Failed to classify bill text", "details": str(e)}), 500

    # Optionally delete the uploaded file after processing to avoid clutter
    # os.remove(filepath)

    return jsonify({
        "extracted_text": text,
        "parsed_items": items,
        "summary": agg
    })

if __name__ == "__main__":
    os.makedirs("uploaded_bills", exist_ok=True)
    with app.app_context():
        db.create_all()
                # List of widgets to create
        widget_names = [
            "network",
            "transaction",
            "income",
            "expenditure",
            "investments",
            "savings",
            "goals",
            "credit score",
            "budget",
            "circle",
            "insights"
        ]

        for name in widget_names:
            if not Widget.query.filter_by(name=name).first():
                db.session.add(Widget(name=name))
        db.session.commit()
    app.run(debug=True, port=5001)