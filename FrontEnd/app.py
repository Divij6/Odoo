# app.py
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import os
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = 'a8f5f167f44f4964e6c998dee827110c3b9a7d6f8e5c0a1b2c3d4e5f6a7b8c9d'

# PostgreSQL Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get(
    'DATABASE_URL',
    'postgresql://postgres:divij123@localhost:5432/ExpenseUser'
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)

db = SQLAlchemy(app)


# ==================== DATABASE MODEL ====================

class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='user')  # admin, manager, user
    full_name = db.Column(db.String(120))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


# ==================== AUTHENTICATION DECORATORS ====================

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)

    return decorated_function


def role_required(*roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                flash('Please log in to access this page.', 'warning')
                return redirect(url_for('login'))

            user = User.query.get(session['user_id'])
            if not user or user.role not in roles:
                flash('You do not have permission to access this page.', 'danger')
                return redirect(url_for('dashboard'))

            return f(*args, **kwargs)

        return decorated_function

    return decorator


# ==================== AUTHENTICATION ROUTES ====================

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        remember = request.form.get('remember') == 'on'

        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password) and user.is_active:
            session.permanent = remember
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role

            # Update last login
            user.last_login = datetime.utcnow()
            db.session.commit()

            flash(f'Welcome back, {user.full_name or user.username}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password.', 'danger')

    return render_template('login.html')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        full_name = request.form.get('full_name')

        # Validation
        if not all([username, email, password, confirm_password]):
            flash('All fields are required.', 'danger')
            return render_template('signup.html')

        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return render_template('signup.html')

        if len(password) < 6:
            flash('Password must be at least 6 characters long.', 'danger')
            return render_template('signup.html')

        # Check if user exists
        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'danger')
            return render_template('signup.html')

        if User.query.filter_by(email=email).first():
            flash('Email already registered.', 'danger')
            return render_template('signup.html')

        # Create new user (default role: user)
        new_user = User(
            username=username,
            email=email,
            full_name=full_name,
            role='user'
        )
        new_user.set_password(password)

        db.session.add(new_user)
        db.session.commit()

        flash('Account created successfully! Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('signup.html')


@app.route('/logout')
@login_required
def logout():
    session.clear()
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('login'))


@app.route('/dashboard')
@login_required
def dashboard():
    user = User.query.get(session['user_id'])

    # Route to appropriate dashboard based on role
    if user.role == 'admin':
        return redirect(url_for('admin_dashboard'))
    elif user.role == 'manager':
        return redirect(url_for('manager_dashboard'))
    else:
        return redirect(url_for('user_dashboard'))


# ==================== ROLE-SPECIFIC DASHBOARDS (EMPTY) ====================

@app.route('/admin/dashboard')
@role_required('admin')
def admin_dashboard():
    user = User.query.get(session['user_id'])
    return render_template('admin_dashboard.html', user=user)


@app.route('/manager/dashboard')
@role_required('manager')
def manager_dashboard():
    user = User.query.get(session['user_id'])
    return render_template('manager_dashboard.html', user=user)


@app.route('/user/dashboard')
@role_required('user')
def user_dashboard():
    user = User.query.get(session['user_id'])
    return render_template('user_dashboard.html', user=user)


# ==================== DATABASE INITIALIZATION ====================

def init_db():
    """Initialize database with default users"""
    with app.app_context():
        db.create_all()

        # Check if admin exists
        if not User.query.filter_by(username='admin1').first():
            # Create admin
            admin = User(
                username='admin1',
                email='admin@atlas.com',
                full_name='System Administrator',
                role='admin'
            )
            admin.set_password('xyz')
            db.session.add(admin)

            # Create manager
            manager = User(
                username='manager1',
                email='manager@atlas.com',
                full_name='Security Manager',
                role='manager'
            )
            manager.set_password('manager123')
            db.session.add(manager)

            # Create user
            user = User(
                username='user1',
                email='user@atlas.com',
                full_name='Regular User',
                role='user'
            )
            user.set_password('user123')
            db.session.add(user)

            db.session.commit()
            print("✅ Default users created successfully!")
            print("Admin: admin1 / xyz")
            print("Manager: manager1 / manager123")
            print("User: user1 / user123")


if __name__ == '__main__':
    init_db()
    app.run(debug=True, host='0.0.0.0', port=5000)