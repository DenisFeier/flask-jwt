from flask import Flask, request, jsonify
from datetime import datetime, timedelta
from jwt import decode, encode, ExpiredSignatureError, InvalidTokenError
import hashlib
import os
import binascii

app = Flask(__name__)

SECRET_KEY = "your_secret_key"

USER_FILE = "users.txt"


def generate_salt():
    return binascii.hexlify(os.urandom(16)).decode()


def hash_password(password, salt):
    return hashlib.sha256((password + salt).encode()).hexdigest()


def save_user(email, password_hash, salt):
    with open(USER_FILE, "a") as file:
        file.write(f"{email}:{password_hash}:{salt}\n")


def find_user(email):
    with open(USER_FILE, "r") as file:
        for line in file:
            stored_email, password_hash, salt = line.strip().split(":")
            if stored_email == email:
                return {"email": stored_email, "password_hash": password_hash, "salt": salt}
    return None


@app.route("/register", methods=["POST"])
def register():
    data = request.get_json()
    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400

    if find_user(email):
        return jsonify({"error": "User already exists"}), 400

    salt = generate_salt()
    password_hash = hash_password(password, salt)

    save_user(email, password_hash, salt)

    return jsonify({"message": "User registered successfully"}), 201


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400

    user = find_user(email)
    if not user:
        return jsonify({"error": "Invalid credentials"}), 401

    password_hash = hash_password(password, user["salt"])

    if password_hash != user["password_hash"]:
        return jsonify({"error": "Invalid credentials"}), 401

    token = encode(
        {
            "email": user["email"],
            "exp": datetime.utcnow() + timedelta(hours=3)
        },
        SECRET_KEY,
        algorithm="HS256"
    )

    return jsonify({"token": token}), 200


@app.route("/get_user", methods=["GET"])
def protected():
    token = request.headers.get("Authorization")

    if not token:
        return jsonify({"error": "Token is missing"}), 401
    try:
        decoded = decode(token, SECRET_KEY, algorithms=["HS256"])
        return jsonify({"message": "You are authenticated", "user": decoded}), 200
    except ExpiredSignatureError:
        return jsonify({"error": "Token has expired"}), 401
    except InvalidTokenError:
        return jsonify({"error": "Invalid token"}), 401


if __name__ == "__main__":
    app.run(debug=True)