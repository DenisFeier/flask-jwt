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


if __name__ == "__main__":
    app.run(debug=True)
