import os
from app import db
from argon2 import PasswordHasher  # Import the PasswordHasher from Argon2
from sqlalchemy.orm import relationship
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

# Initialize the Argon2 Password Hasher
ph = PasswordHasher()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)  # Store Argon2 hash
    master_salt = db.Column(db.String, nullable=False)
    session_timeout = db.Column(db.Integer, default=15)  # Default 15 minutes
    passwords = db.relationship('Password', backref='owner', lazy=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Set the password using Argon2 hashing
    def set_password(self, password):
        self.password_hash = ph.hash(password)  # Hash password with Argon2

    # Check the password using Argon2 hash verification
    def check_password(self, password):
        try:
            return ph.verify(self.password_hash, password)  # Verify password with Argon2
        except:
            return False  # If verification fails, return False

    @staticmethod
    def generate_salt():
        """Generate a random salt if you want to store salt manually."""
        return os.urandom(16).hex()

class Password(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    website = db.Column(db.String(255), nullable=False)
    encrypted_password = db.Column(db.Text, nullable=False)  # 🔐 Encrypted password (Base64)
    iv = db.Column(db.String(64), nullable=False)             # 🔹 AES IV (Base64)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
