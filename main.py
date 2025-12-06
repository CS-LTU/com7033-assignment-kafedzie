import os
import pandas as pd
from dotenv import load_dotenv
from bson import ObjectId

from flask import Flask, render_template, redirect, request, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_pymongo import PyMongo
from flask_wtf import CSRFProtect, FlaskForm
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user

from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import Email, DataRequired, Length, EqualTo, ValidationError
from werkzeug.security import generate_password_hash, check_password_hash


#Load environment
load_dotenv()

app = Flask(__name__)

# ----Core configuration
basedir = os.path.abspath(os.path.dirname(__file__))

# Secret key for sessions
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-unsafe-secret")

# SQLite for authentication (users)
auth_db_path = os.path.join(basedir, "auth.db")
app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{auth_db_path}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# MongoDB for patient records
app.config["MONGO_URI"] = os.getenv("MONGO_URI", "mongodb://localhost:27017/COM7033")

# Secure session cookie settings
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax" 

# Extensions
db = SQLAlchemy(app)          # SQLite (auth)
mongo = PyMongo(app)          # MongoDB (patients)
csrf = CSRFProtect(app)       # CSRF protection
login_manager = LoginManager(app)  # handles user sessions

# Where to redirect if @login_required hits an anonymous user
login_manager.login_view = "login"
login_manager.login_message = "Please log in to access this page"
login_manager.login_message_category = "info"

@login_manager.user_loader
def load_user(user_id):
    """Load user from the database by ID (for Flask-Login)."""
    return User.query.get(int(user_id))

class User(UserMixin, db.Model):
    """User account stored in SQLite for authentication."""
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)  # hashed password

    def __repr__(self):
        return f"<User {self.email}>"
    
    def set_password(self, password):
        """Hash and set the user's password."""
        self.password_hash = generate_password_hash(password, method='pbkdf2:sha256')

    def check_password(self, password):
        """Verify the password against the stored hash."""
        return check_password_hash(self.password_hash, password)

# -----------------------
# Forms (use Flask-WTF for CSRF + validation)
# -----------------------

class RegistrationForm(FlaskForm):
    email = StringField(
        "Email",
        validators=[
            DataRequired(),
            Email(message="Please enter a valid email address."),
            Length(max=120),
        ],
    )
    password = PasswordField(
        "Password",
        validators=[
            DataRequired(),
            Length(min=8, message="Password must be at least 8 characters."),
        ],
    )
    confirm_password = PasswordField(
        "Confirm Password",
        validators=[
            DataRequired(),
            EqualTo("password", message="Passwords must match."),
        ],
    )
    submit = SubmitField("Register")

    def validate_email(self, field):
        # Custom validator to ensure email is unique
        if User.query.filter_by(email=field.data.lower()).first():
            raise ValidationError("An account with this email already exists.")


class LoginForm(FlaskForm):
    email = StringField(
        "Email",
        validators=[DataRequired(), Email(), Length(max=120)],
    )
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")

# Routes

@app.route("/")
def home():
    return render_template("home.html")

@app.route("/patients")
@login_required
def list_patients():
    # We'll replace this with real MongoDB logic soon
    return "Patients page (MongoDB-backed patient records will go here)."


# -----------------------
# Authentication routes
# -----------------------

@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        email = form.email.data.lower()
        password = form.password.data

        # Create new user with hashed password
        user = User(email=email)
        user.set_password(password)
    try:    
        db.session.add(user)
        db.session.commit()
        flash("Registration successful. You can now log in.", "success")
        return redirect(url_for("login"))
    except Exception as e:
        db.session.rollback()
        flash("Registration failed. Please try again.", "danger")
        app.logger.error(f"Registration error: {e}")

    return render_template("register.html", form=form)


@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data.lower()
        password = form.password.data

        user = User.query.filter_by(email=email).first()

        if user and user.check_password(password):
            login_user(user)
            flash("Logged in successfully.", "success")
            # Later you can redirect to next or patients
            return redirect(url_for("home"))
        else:
            flash("Invalid email or password.", "danger")

    return render_template("login.html", form=form)

#Log out the current user
@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for("home"))


# CLI helper (run & create tables)
# -----------------------
if __name__ == "__main__":
    with app.app_context():
        db.create_all()  # ensure auth.db and User table exist
    app.run(debug=True)
