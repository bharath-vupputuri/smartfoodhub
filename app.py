import os
import logging
from flask import Flask, render_template, redirect, url_for, request, flash,jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, HiddenField
from wtforms.validators import InputRequired, Length, Email, Regexp
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import google.generativeai as genai

GEMINI_API_KEY = "AIzaSyBkCxP-RwWc4-qqBfFvJ9HKxlBLlgN4g2w"  
genai.configure(api_key=GEMINI_API_KEY)
model = genai.GenerativeModel("gemini-1.5-flash")

# Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Flask App Configuration
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize Extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'


# User Model
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    phone = db.Column(db.String(15), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)
    role = db.Column(db.String(10), nullable=False)
    
class MenuItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    group_type = db.Column(db.String(50), nullable=False)  # Example: 'Main Course', 'Appetizer', etc.
    price = db.Column(db.Float, nullable=False)
    image = db.Column(db.String(255))  # Image URL

    def __init__(self, name, group_type, price, image):
        self.name = name
        self.group_type = group_type
        self.price = price
        self.image = image


# Registration Form
class RegisterForm(FlaskForm):
    name = StringField('Full Name', validators=[InputRequired(), Length(min=4, max=50)])
    email = StringField('Email', validators=[InputRequired(), Email(), Length(max=100)])
    phone = StringField('Phone Number', validators=[
        InputRequired(), Length(min=10, max=15), Regexp(r'^\d+$', message="Phone number must contain only digits.")
    ])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=6, max=80)])
    role = HiddenField('Role', validators=[InputRequired()])
    submit = SubmitField('Register')


# Login Form
class LoginForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired(), Email(), Length(max=100)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=6, max=80)])
    submit = SubmitField('Login')


# Load User for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    logger.debug(f'Loading user with ID: {user_id}')
    return User.query.get(int(user_id))


@app.route('/')
def landing():
    return render_template('landing.html')


# Register Route
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        new_user = User(
            name=form.name.data,
            email=form.email.data,
            phone=form.phone.data,
            password=hashed_password,
            role=form.role.data
        )
        try:
            db.session.add(new_user)
            db.session.commit()
            logger.info(f'User {new_user.email} registered successfully')
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            logger.error(f'Error registering user: {e}')
            flash('Email or phone number already exists or another error occurred.', 'danger')
    else:
        logger.debug(f'Form validation failed with errors: {form.errors}')
        flash('Please check your input and try again.', 'danger')

    return render_template('register.html', form=form)


# Login Route
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)

            logger.debug(f"User {user.email} logged in with role: {user.role}")

            if user.role == 'restaurant':
                return redirect(url_for('restaurant_dashboard'))
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password', 'danger')

    return render_template('login.html', form=form)


# Dashboard Route (Protected)
@app.route('/dashboard')
@login_required
def dashboard():
    logger.debug(f'User {current_user.email} accessed dashboard')
    return render_template('dashboard.html')

#restaurant_dashboard Route (Protected)
@app.route('/restaurant_dashboard')
@login_required
def restaurant_dashboard():
    return render_template('restaurant_dashboard.html')

@app.route("/chat", methods=["POST"])
def chat():
    data = request.json
    user_message = data.get("message", "").strip()

    if not user_message:
        return jsonify({"error": "Empty message"}), 400

    try:
        # Call Gemini API
        response = model.generate_content(user_message)
        bot_reply = response.text if response.text else "Sorry, I couldn't understand that."
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    return jsonify({"reply": bot_reply})
    
# Cart Route (Protected)
@app.route('/cart')
@login_required
def cart():
    logger.debug(f'User {current_user.email} accessed cart')
    return render_template('cart.html', user=current_user)


# Delete Address Route (Protected)
@app.route('/del_address')
@login_required
def del_address():
    logger.debug(f'User {current_user.email} accessed del_address')
    return render_template('del_address.html',user=current_user)

@app.route('/payment')
@login_required
def payment():
    logger.debug(f'User {current_user.email} accessed payment')
    return render_template('payment.html',user=current_user)

@app.route('/delivery_tracking')
@login_required
def delivery_tracking():
    logger.debug(f'User {current_user.email} accessed delivery_tracking')
    return render_template('delivery_tracking.html',user=current_user)

@app.route('/restaurant_menu')
def restaurant_menu():
    return render_template('restaurant_menu.html')

@app.route('/restaurant_orders')
def restaurant_orders():
    return render_template('restaurant_orders.html')

@app.route('/restaurant_review')
def restaurant_review():
    return render_template('restaurant_review.html')

@app.route('/restaurant_settings')
def restaurant_settings():
    return render_template('restaurant_settings.html')


@app.route('/restaurant_additem', methods=['GET', 'POST'])
def restaurant_additem():
    if request.method == 'POST':
        name = request.form['name']
        group_type = request.form['group']
        price = float(request.form['price'])
        image = request.form['image']

        new_item = MenuItem(name=name, group_type=group_type, price=price, image=image)
        db.session.add(new_item)
        db.session.commit()
        menu_items = MenuItem.query.all()
    return render_template('restaurant_additem.html', menu_items=menu_items)

@app.route('/logout')
@login_required
def logout():
    logger.info(f'User {current_user.email} logged out')
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))


@app.route('/home')
@login_required
def home():
    return render_template('home.html', user=current_user)


# Create Database Tables if They Don't Exist
if __name__ == '__main__':
    if not os.path.exists("users.db"):
        with app.app_context():
            db.create_all()
            logger.info('Database initialized successfully!')
    logger.info('Starting Flask application...')
    app.run(debug=True)
