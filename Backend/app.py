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

app = Flask(__name__)
CORS(app)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///data.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = "your-secret-key"  # Change to secure secret

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


# Utilities
def generate_token(user_id):
    payload = {
        "user_id": user_id,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=24)
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
    client = genai.Client(
        api_key="AIzaSyB-OpV4Xb1mCQcVOLZDTJdHWCm5TRNjO_w",
    )

    model = "gemini-2.5-pro"
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

    for chunk in client.models.generate_content_stream(
        model=model,
        contents=contents,
        config=generate_content_config,
    ):
        print(chunk.text, end="")
    response = {
        "user_id": user_id,
        "query": query,
        "insight": f"Demo insight for query '{chunk.text}'"
    }
    return jsonify(response)

@app.route("/user/<int:user_id>/widgets", methods=["GET"])
@auth_required
def get_user_widgets(user_id_token):
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
def update_widget_visibility(user_id_token, widget_id):
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


if __name__ == "__main__":
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
    app.run(debug=True)
