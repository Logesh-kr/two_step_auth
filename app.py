from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import random

app = Flask(__name__)
app.config['SECRET_KEY'] = 'replace_with_secure_random_value'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.permanent_session_lifetime = timedelta(minutes=30)


# In-memory stores (for production, use a persistent DB)
users = {}      # { email: { 'password_hash': ..., ... } }
otp_store = {}  # { email: { 'otp': ..., 'expires_at': datetime, 'attempts': int } }

OTP_VALIDITY = timedelta(minutes=5)
MAX_OTP_ATTEMPTS = 3


@app.route('/')
def home():
    return redirect(url_for('register'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        if not email or not password:
            flash('Email and password required.')
            return redirect(url_for('register'))
        if email in users:
            flash('Email already registered.')
            return redirect(url_for('register'))
        password_hash = generate_password_hash(password)
        users[email] = {'password_hash': password_hash}
        flash('Registered successfully. Please log in.')
        return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        user = users.get(email)
        if user and check_password_hash(user['password_hash'], password):
            otp = '{:06d}'.format(random.randint(0, 999999))
            expires_at = datetime.utcnow() + OTP_VALIDITY
            otp_store[email] = {'otp': otp, 'expires_at': expires_at, 'attempts': 0}
            # TODO: send OTP via email/SMS instead of print
            print(f'OTP for {email}: {otp}')
            session.clear()
            session['email'] = email
            session.permanent = True
            return redirect(url_for('verify'))
        else:
            flash('Invalid credentials.')
            return redirect(url_for('login'))
    return render_template('login.html')


@app.route('/verify', methods=['GET', 'POST'])
def verify():
    email = session.get('email')
    if not email:
        flash('Session expired or invalid. Please log in again.')
        return redirect(url_for('login'))

    otp_data = otp_store.get(email)
    if not otp_data:
        flash('No OTP request found. Please log in again.')
        return redirect(url_for('login'))

    if request.method == 'POST':
        otp_entered = request.form.get('otp', '').strip()
        now = datetime.utcnow()

        if now > otp_data['expires_at']:
            flash('OTP expired. Please log in again.')
            otp_store.pop(email, None)
            return redirect(url_for('login'))

        otp_data['attempts'] += 1
        if otp_data['attempts'] > MAX_OTP_ATTEMPTS:
            flash('Too many attempts. Please log in again.')
            otp_store.pop(email, None)
            return redirect(url_for('login'))

        if otp_entered == otp_data['otp']:
            otp_store.pop(email, None)
            session['authenticated'] = True
            # ✅ Render the styled success page instead of plain text
            return render_template('success.html')
        else:
            flash('Invalid OTP.')
            return redirect(url_for('verify'))

    return render_template('verify.html')


@app.route('/home')
def home_page():
    if not session.get('authenticated'):
        flash('Please log in first.')
        return redirect(url_for('login'))
    return 'Welcome to the Home Page!'


if __name__ == '__main__':
    app.run(debug=True)
