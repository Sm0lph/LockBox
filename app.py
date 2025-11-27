from flask import Flask, session
from flask_sqlalchemy import SQLAlchemy
from flask_session import Session
from flask_migrate import Migrate
from flask_bcrypt import Bcrypt
from datetime import timedelta
import jwt
import datetime
import os

app = Flask(__name__)

# ------------------------------
# ✅ Database Configuration
# ------------------------------
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# ------------------------------
# ✅ Session Configuration
# ------------------------------
app.config['SESSION_TYPE'] = 'filesystem'              # Use server-side session storage
app.config['SESSION_FILE_DIR'] = './flask_session_dir' # Directory to store session files
app.config['SESSION_PERMANENT'] = True
app.config['SECRET_KEY'] = '!tU830MK#$PKVMW!'           # Used for securely signing the session cookie
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

# ------------------------------
# ✅ Extensions Initialization
# ------------------------------
db = SQLAlchemy(app, session_options={"autocommit": False, "autoflush": False})
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)
Session(app)

# ------------------------------
# ✅ Debug: Log Session Details on Startup
# ------------------------------
@app.before_request
def debug_session_info():
    if 'user_id' in session:
        print(f"🟢 Session Active | user_id: {session.get('user_id')}, first_name: {session.get('first_name')}")
    else:
        print("🔴 No active session found.")

# ------------------------------
# ✅ Import routes after app init
# ------------------------------
from routes import *

# ------------------------------
# ✅ Main Entry Point
# ------------------------------
if __name__ == '__main__':
    # Create session directory if it doesn't exist
    os.makedirs(app.config['SESSION_FILE_DIR'], exist_ok=True)
    print("🚀 LockBox app is starting...")
    app.run(debug=True, threaded=True)
