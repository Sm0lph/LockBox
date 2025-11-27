from flask import request, jsonify, render_template, session, redirect, url_for, flash
from app import app, db
from models import User, Password
from flask_argon2 import Argon2  
from datetime import timedelta
from Crypto.Protocol.KDF import PBKDF2
import base64
import os
import re
import jwt
import datetime
from flask_login import login_required, current_user
import bcrypt

# Initialize Flask-Argon2 for password hashing
argon2 = Argon2(app)

# App Configuration for Session Timeout
app.config['SECRET_KEY'] = 'tU830MK#$PK'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)  # Auto logout after 30 min

# Password Strength Regex Pattern
PASSWORD_REGEX = re.compile(r"^(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{8,}$")

#--------------------------------------------------------------------------------------

@app.before_request
def manage_session():
    if 'user_id' in session:
        now = datetime.datetime.utcnow().timestamp()
        timeout = session.get('timeout', 15) * 60  # Convert minutes to seconds, default 15 minutes
        last_active = session.get('last_active', now)

        if now - last_active > timeout:
            session.clear()
            flash("⏳ Session expired. Please log in again.", "warning")
            return redirect(url_for('login'))

        session['last_active'] = now

#--------------------------------------------------------------------------------------

# Register Route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        data = request.form
        email = data.get('email')
        password = data.get('password')
        confirm_password = data.get('confirm_password')
        first_name = data.get('first_name')
        last_name = data.get('last_name')
        master_salt = base64.b64encode(os.urandom(16)).decode('utf-8') # Generate a unique salt per user (128-bit, base64 encoded)


        def is_valid_email(email):
            email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
            return re.match(email_regex, email)

        if not is_valid_email(email):
            return render_template('registration.html', error="⚠️ Please enter a valid email address")

        if not all([email, password, confirm_password, first_name, last_name]):
            return render_template('registration.html', error="⚠️ All fields are required")

        if password != confirm_password:
            return render_template('registration.html', error="❌ Passwords do not match")

        # ✅ Check Password Strength
        if not PASSWORD_REGEX.match(password):
            return render_template(
                'registration.html',
                error="⚠️ Password must be at least 8 characters long, contain one uppercase letter, one number, and one special character."
            )

        if User.query.filter_by(email=email).first():
            return render_template('registration.html', error="⚠️ Email already exists")

        # ✅ Hash password using Argon2
        hashed_password = argon2.generate_password_hash(password)

        # ✅ Create a new user
        new_user = User(
            first_name=first_name,
            last_name=last_name,
            email=email,
            password_hash=hashed_password,  # Use hashed password from Argon2
            master_salt=master_salt
            )
       

        db.session.add(new_user)
        db.session.commit()
        db.session.close()

        flash("✅ Registration successful! Please log in.", "success")
        return redirect(url_for('login'))

    return render_template('registration.html')

#--------------------------------------------------------------------------------------

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('Login.html')

    # Check if it's an AJAX request
    is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest'
    
    data = request.form
    email = data.get('email')
    password_input = data.get('password')

    if not email or not password_input:
        if is_ajax:
            return jsonify({'success': False, 'error': "Email and password are required"}), 400
        return render_template('Login.html', error="⚠️ Email and password are required")

    user = User.query.filter_by(email=email).first()
    if not user:
        if is_ajax:
            return jsonify({'success': False, 'error': "Invalid credentials"}), 401
        return render_template('Login.html', error="❌ Invalid credentials")

    try:
        # Check the hashed password
        if argon2.check_password_hash(user.password_hash, password_input):
            session.clear()
            session.permanent = True
            session['user_id'] = user.id
            session['first_name'] = user.first_name
            session['last_active'] = datetime.datetime.utcnow().timestamp()
            session['master_salt'] = user.master_salt

            if is_ajax:
                return jsonify({
                    'success': True,
                    'userId': user.id,
                    'master_salt': user.master_salt,
                    'redirect': url_for('Dashboard')
                })

            # For regular form submissions, redirect as before
            response = redirect(url_for('Dashboard'))
            response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
            response.headers['Pragma'] = 'no-cache'
            response.headers['Expires'] = '0'
            return response
        else:
            if is_ajax:
                return jsonify({'success': False, 'error': "Invalid credentials"}), 401
            return render_template('Login.html', error="❌ Invalid credentials")

    except Exception as e:
        print(f"🔥 Error during login: {e}")
        if is_ajax:
            return jsonify({'success': False, 'error': str(e)}), 500
        return render_template('Login.html', error="🔥 An error occurred")


#--------------------------------------------------------------------------------------

# Logout Route
@app.route('/logout')
def logout():
    session.clear()  # 💥 Wipe session from server

    response = redirect(url_for('home'))
    response.set_cookie('session', '', expires=0)  # 🔥 Delete session cookie from browser
    print("📦 Flask Session after logout:", dict(session))
    return response


#--------------------------------------------------------------------------------------

# Homepage Route
@app.route('/', methods=['GET'])
def home():
    first_name = session.get('first_name')  # Get user's first name from session
    return render_template('Home.html', first_name=first_name)

#--------------------------------------------------------------------------------------

# Generator Route
@app.route('/Generator', methods=['GET'])
def generator():
    return render_template('Generator.html')

#--------------------------------------------------------------------------------------

@app.route('/Dashboard', methods=['GET'])
def Dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    passwords = Password.query.filter_by(user_id=user_id).all()  # Fetch all passwords for the user
    first_name = session.get('first_name')

    # Retrieve AES key, salt, and IV from session
    aes_key = session.get('aes_key')  # Ensure you set this in the session after login
    master_salt = session.get('master_salt')  # Assuming this is stored in session
    iv = session.get('iv')  # Ensure IV is stored in session after login

    if iv is None:
        print("IV is not stored in the session!")  # Debugging line

    # Pass the AES key, salt, and IV to the dashboard template
    return render_template('Dashboard.html', passwords=passwords, first_name=first_name, aes_key=aes_key, salt=master_salt, iv=iv)


#--------------------------------------------------------------------------------------

@app.route('/add_password', methods=['POST'])
def add_password():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401

    try:
        # Debugging logs
        print("📝 Content-Type:", request.content_type)
        print("📝 Headers:", dict(request.headers))
        body_data = request.get_data(as_text=True)
        print("📝 Raw Body:", body_data)

        data = request.get_json()
        if data is None:
            print("❌ Failed to parse JSON data")
            return jsonify({'success': False, 'message': 'Invalid JSON format'}), 400

        print("📦 Parsed JSON data:", data)

        website = data.get('website')
        encrypted_password = data.get('ciphertext')
        iv = data.get('iv')
        user_id = session['user_id']

        # Validate required fields
        if not website or not encrypted_password or not iv:
            missing_fields = []
            if not website: missing_fields.append('website')
            if not encrypted_password: missing_fields.append('ciphertext')
            if not iv: missing_fields.append('iv')
            print("❌ Missing fields:", missing_fields)
            return jsonify({
                'success': False, 
                'message': f'Missing required fields: {", ".join(missing_fields)}'
            }), 400

        try:
            new_password = Password(
                website=website,
                encrypted_password=encrypted_password,
                iv=iv,
                user_id=user_id
            )

            db.session.add(new_password)
            db.session.commit()
            print("✅ Password added successfully")

            return jsonify({
                'success': True, 
                'message': 'Password added successfully!'
            })

        except Exception as e:
            db.session.rollback()
            print(f"❌ Database error: {str(e)}")
            print(f"Error type: {type(e)}")
            import traceback
            print("Full traceback:")
            print(traceback.format_exc())
            return jsonify({
                'success': False, 
                'message': f'Database error: {str(e)}'
            }), 500

    except Exception as e:
        print(f"❌ General error: {str(e)}")
        print(f"Error type: {type(e)}")
        import traceback
        print("Full traceback:")
        print(traceback.format_exc())
        return jsonify({
            'success': False, 
            'message': f'Server error: {str(e)}'
        }), 500

#--------------------------------------------------------------------------------------

@app.route('/delete_password/<int:id>', methods=['POST'])
def delete_password(id):
    # Check if the user is logged in
    if 'user_id' not in session:
        flash('Unauthorized access', 'error')
        return redirect(url_for('login'))  # Redirect to login if not authenticated

    # Fetch the password entry to delete
    password_entry = Password.query.get(id)

    # Check if the password exists and belongs to the logged-in user
    if not password_entry or password_entry.user_id != session['user_id']:
        flash('Password not found', 'error')
        return redirect(url_for('Dashboard'))  # Redirect back to the dashboard if not found

    # Delete the password entry from the database
    db.session.delete(password_entry)
    db.session.commit()

    # Flash success message
    flash('Password deleted successfully', 'success')

    # Redirect to the dashboard after deletion
    return redirect(url_for('Dashboard'))

#--------------------------------------------------------------------------------------

@app.route('/get_salt', methods=['GET'])
def get_salt():
    # You should generate or retrieve a unique salt for each user session
    salt = os.urandom(16).hex()  # Example salt generation
    return jsonify({'salt': salt})

#--------------------------------------------------------------------------------------

@app.route('/get_encrypted_password', methods=['GET'])
def get_encrypted_password():
    password_id = request.args.get('id')
    if not password_id:
        return jsonify({'error': 'Missing password ID'}), 400

    password_entry = Password.query.get(password_id)
    if password_entry is None:
        return jsonify({'error': 'Password not found'}), 404

    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'error': 'User not logged in'}), 401

    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404

    # Ensure the password belongs to the user (important!)
    if password_entry.user_id != user_id:
        return jsonify({'error': 'Unauthorized access'}), 403

    return jsonify({
        'encrypted_password': password_entry.encrypted_password,
        'iv': password_entry.iv
    }), 200


#--------------------------------------------------------------------------------------

#route to the settings Page
@app.route('/Settings', methods=['GET'])
def Settings():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    user = User.query.filter_by(id=user_id).first()

    if not user:
        return redirect(url_for('login'))  

    return render_template('Settings.html', first_name=user.first_name)

@app.route('/settings')
def settings():
    # Check if user is logged in
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    user = User.query.get(user_id)
    if not user:
        session.clear()
        return redirect(url_for('login'))

    # Get password statistics
    user_passwords = Password.query.filter_by(user_id=user_id).all()
    total_passwords = len(user_passwords)
    
    # Get the most recent password update time
    last_update = None
    if user_passwords:
        last_update = max(p.created_at for p in user_passwords)
        time_diff = datetime.datetime.utcnow() - last_update
        
        if time_diff.days > 30:
            months = time_diff.days // 30
            time_ago = f"{months} months ago"
        elif time_diff.days > 0:
            time_ago = f"{time_diff.days} days ago"
        elif time_diff.seconds >= 3600:
            hours = time_diff.seconds // 3600
            time_ago = f"{hours} hours ago"
        elif time_diff.seconds >= 60:
            minutes = time_diff.seconds // 60
            time_ago = f"{minutes} minutes ago"
        else:
            time_ago = "Just now"
    else:
        time_ago = "No passwords saved yet"

    # Get current timeout value
    current_timeout = session.get('timeout', 15)

    return render_template('Settings.html',
                         first_name=user.first_name,
                         total_passwords=total_passwords,
                         last_update=time_ago,
                         current_timeout=current_timeout)

#--------------------------------------------------------------------------------------

@app.route('/update_session_timeout', methods=['POST'])
def update_session_timeout():
    try:
        # Check if user is logged in
        if 'user_id' not in session:
            return jsonify({'success': False, 'message': 'Not logged in'}), 401

        data = request.get_json()
        timeout = data.get('timeout', 15)  # Default to 15 minutes if not specified
        
        # Store timeout in session
        session['timeout'] = timeout
        session['last_active'] = datetime.datetime.utcnow().timestamp()
        
        # Update user's session_timeout in database
        user = User.query.get(session['user_id'])
        if user:
            user.session_timeout = timeout
            db.session.commit()
        
        return jsonify({'success': True})
    except Exception as e:
        print(f"Error in update_session_timeout: {str(e)}")  # Add logging
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/delete_all_data', methods=['POST'])
def delete_all_data():
    try:
        # Check if user is logged in
        if 'user_id' not in session:
            return jsonify({'success': False, 'message': 'Not logged in'}), 401

        user_id = session['user_id']
        
        # Delete all passwords for the user
        Password.query.filter_by(user_id=user_id).delete()
        
        # Delete the user account
        user = User.query.get(user_id)
        if user:
            db.session.delete(user)
        
        # Commit the changes
        db.session.commit()
        
        # Clear the session
        session.clear()
        
        return jsonify({
            'success': True,
            'redirect': url_for('home')
        })
    except Exception as e:
        print(f"Error in delete_all_data: {str(e)}")  # Add logging
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500
