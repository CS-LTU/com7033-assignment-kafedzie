import os
import pandas as pd
from dotenv import load_dotenv
from bson import ObjectId
from bson.errors import InvalidId
from functools import wraps

from datetime import timedelta
from flask import Flask, render_template, redirect, request, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_pymongo import PyMongo
from flask_wtf import CSRFProtect, FlaskForm
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user

from wtforms import StringField, PasswordField, SubmitField, SelectField
from wtforms.validators import Email, DataRequired, Length, EqualTo, ValidationError
from werkzeug.security import generate_password_hash, check_password_hash


# Load environment
load_dotenv()

app = Flask(__name__)

# Core configuration
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
app.config["SESSION_COOKIE_SECURE"] = False

# Session persistence
app.config["SESSION_PERMANENT"] = True
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=24)

# Extensions
db = SQLAlchemy(app)          # SQLite (auth)
mongo = PyMongo(app)          # MongoDB (patients)
csrf = CSRFProtect(app)       # CSRF protection
login_manager = LoginManager(app)  # Handles user sessions

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
    password_hash = db.Column(db.String(200), nullable=False)  # Hashes password
    role = db.Column(db.String(20), nullable=False, default='user')
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())

    def __repr__(self):
        return f"<User {self.email}>"
    
    def set_password(self, password):
        """Hash and set the user's password."""
        self.password_hash = generate_password_hash(password, method='pbkdf2:sha256')

    def check_password(self, password):
        """Verify the password against the stored hash."""
        return check_password_hash(self.password_hash, password)
    
    def is_admin(self):
        """Check if user is an Administrator"""
        return self.role == "admin"
    
    def is_general_user(self):
        """Check if user is a general user"""
        return self.role == "user"

# ========= Role based access control decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            flash("Please log in to access this page.", "warning")
            return redirect(url_for('login'))
            
        if not current_user.is_admin():
            flash("Access denied. Admin privileges required.", "danger")
            return redirect(url_for('home'))
        
        return f(*args, **kwargs)
    return decorated_function

#------------------
# Helper Functions
#------------------  
def validate_object_id(patient_id):
    """Validate that a string is a valid MongoDB ObjectId"""
    try:
        return ObjectId(patient_id)
    except(InvalidId, TypeError):
        return None

# -----------------------
# Forms (Flask-WTF for CSRF + validation)
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

class ForgotPasswordForm(FlaskForm ):
    """Forms for user to request password reset"""
    email = StringField(
        "Email",
        validators=[DataRequired(), Email(), Length(max=120)], 
    )
    submit = SubmitField("Reset Password")

class ResetPasswordForm(FlaskForm):
    """Forms for user to reset password"""
    email = StringField(
        "Email",
        validators=[DataRequired(), Email(), Length(max=120)],
    )
    new_password = PasswordField(
        """New Password""",
        validators=[
            DataRequired(),
            Length(min=8, message="Password must be at least 8 characters"),
        ],
    )
    confirm_password = PasswordField(
        "Confirm new password",
        validators=[
            DataRequired(),
            EqualTo("new_password", message="Passwords must match"),
            ],
    )
    submit = SubmitField("Reset Password")

class CreateUserForm(FlaskForm):
    """Administrator form to create new users"""
    email = StringField(
        "Email",
        validators=[DataRequired(), Email(), Length(max=120)]
    )
    password = PasswordField(
        "Password",
        validators=[DataRequired(), Length(max=120)],
    )
    role = SelectField(
        "Role",
        choices=[('user', 'General User'), ('admin', 'Administrator')],
        validators=[DataRequired()]
    )
    submit = SubmitField("Create User")


# ===== PUBLIC ROUTE =====

@app.route("/")
def home():
    # Redirect logged-in users to patients list
    if current_user.is_authenticated:
        return redirect(url_for("list_patients"))
    return render_template("home.html")

# ===== AUTHENTICATION ROUTES =====

@app.route("/register", methods=["GET", "POST"])
def register():
    """User Registration Page"""
    if current_user.is_authenticated:
        return redirect(url_for("list_patients"))
    
    form = RegistrationForm()
    
    if form.validate_on_submit():
        email = form.email.data.lower()
        password = form.password.data
        
        # Create new user (default role is 'user')
        new_user = User(email=email, role='user')
        new_user.set_password(password)
        
        try:
            db.session.add(new_user)
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
    """User Login page"""
    # Redirect if already logged in
    if current_user.is_authenticated:
        print(f"User already authenticated: {current_user.email}")
        return redirect(url_for("list_patients"))
    
    form = LoginForm()
    
    if form.validate_on_submit():
        email = form.email.data.lower()
        password = form.password.data
        
        print(f"Login attempt for: {email}")
        user = User.query.filter_by(email=email).first()

        if user:
            print(f"DEBUG: User found in database")
            if user.check_password(password):
                print(f"DEBUG: Password check PASSED")
                
                # Log the user in
                login_user(user, remember=True)
                session.permanent = True
                
                print(f"DEBUG: After login_user()")
                print(f"DEBUG: current_user.is_authenticated = {current_user.is_authenticated}")
                print(f"DEBUG: current_user.id = {current_user.get_id()}")
                
                flash(f"Logged in successfully. Welcome, {user.email}!", "success")
                
                # Get next page
                next_page = request.args.get('next')
                
                # Security: Only allow relative URLs
                if next_page and not next_page.startswith('/'):
                    next_page = None
                
                redirect_url = next_page or url_for("list_patients")
                print(f"DEBUG: Redirecting to: {redirect_url}")
                
                return redirect(redirect_url)
            else:
                print(f"DEBUG: Password check FAILED")
                flash("Invalid email or password.", "danger")
        else:
            print(f"DEBUG: User NOT found in database")
            flash("Invalid email or password.", "danger")

    return render_template("login.html", form=form)

@app.route("/logout")
@login_required
def logout():
    """Log out the current user"""
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for("home"))

# ===== PASSWORD RESET ROUTES =====

@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    """Password reset request page"""
    if current_user.is_authenticated:
        return redirect(url_for("list_patients"))
    
    form = ForgotPasswordForm()
    
    if form.validate_on_submit():
        email = form.email.data.lower()
        user = User.query.filter_by(email=email).first()
        
        if user:
            # Dummy message
            flash(
                "If an account exists with that email, password reset instructions have been sent. "
                "For now, please contact an administrator to reset your password.",
                "info"
            )
        else:
            flash(
                "If an account exists with that email, password reset instructions have been sent.",
                "info"
            )
        
        return redirect(url_for("login"))
    
    return render_template("forgot_password.html", form=form)

@app.route("/reset-password", methods=["GET", "POST"])
@admin_required
def reset_password():
    """Admin-only password reset page"""
    form = ResetPasswordForm()
    
    if form.validate_on_submit():
        email = form.email.data.lower()
        new_password = form.new_password.data
        
        user = User.query.filter_by(email=email).first()
        
        if user:
            user.set_password(new_password)
            db.session.commit()
            flash(f"Password reset successfully for {email}.", "success")
            return redirect(url_for("admin_panel"))
        else:
            flash(f"User {email} not found.", "danger")    
    return render_template("reset_password.html", form=form)


 # ===== ADMIN PANEL =====

@app.route("/admin")
@admin_required
def admin_panel():
    """Admin dashboard"""
    users = User.query.order_by(User.created_at.desc()).all()
    total_patients = mongo.db.patients.count_documents({})
    
    return render_template(
        "admin_panel.html",
        users=users,
        total_patients=total_patients
    )


@app.route("/admin/users/create", methods=["GET", "POST"])
@admin_required
def admin_create_user():
    """Admin page to create new users"""
    form = CreateUserForm()
    
    if form.validate_on_submit():
        email = form.email.data.lower()
        password = form.password.data
        role = form.role.data
        
        # Check if user already exists
        if User.query.filter_by(email=email).first():
            flash(f"User {email} already exists.", "danger")
        else:
            new_user = User(email=email, role=role)
            new_user.set_password(password)
            
            try:
                db.session.add(new_user)
                db.session.commit()
                flash(f"User {email} created successfully with role: {role}.", "success")
                return redirect(url_for("admin_panel"))
            except Exception as e:
                db.session.rollback()
                flash("Failed to create user. Please try again.", "danger")
                app.logger.error(f"User creation error: {e}")
    
    return render_template("admin_create_user.html", form=form)


@app.route("/admin/users/<int:user_id>/toggle-role", methods=["POST"])
@admin_required
def admin_toggle_role(user_id):
    """Toggle user role between admin and user"""
    user = User.query.get_or_404(user_id)
    
    # Prevent admin from removing their own admin privileges
    if user.id == current_user.id:
        flash("You cannot change your own role.", "warning")
        return redirect(url_for("admin_panel"))
    
    # Toggle role
    user.role = 'user' if user.role == 'admin' else 'admin'
    db.session.commit()
    
    flash(f"User {user.email} role changed to: {user.role}", "success")
    return redirect(url_for("admin_panel"))


@app.route("/admin/users/<int:user_id>/delete", methods=["POST"])
@admin_required
def admin_delete_user(user_id):
    """Delete a user account"""
    user = User.query.get_or_404(user_id)
    
    # Prevent admin from deleting themselves
    if user.id == current_user.id:
        flash("You cannot delete your own account.", "warning")
        return redirect(url_for("admin_panel"))
    
    email = user.email
    db.session.delete(user)
    db.session.commit()
    
    flash(f"User {email} deleted successfully.", "success")
    return redirect(url_for("admin_panel"))

# -----------------------
# Patient Management Routes
# -----------------------

@app.route("/patients")
@login_required
def list_patients():
    gender = request.args.get("gender")
    stroke = request.args.get("stroke")
    smoking = request.args.get("smoking_status")

    query = {}

    if gender:
        query["gender"] = gender
    if stroke:
        query["stroke"] = stroke
    flash("Invalid stroke filter value.", "warning")
    if smoking:
        query["smoking_status"] = smoking

    collection = mongo.db.patients

    patients_cursor = collection.find(query).sort("_id", -1)  # newest first
    page = request.args.get('page', 1, type=int)
    per_page = 30
    patients = list(patients_cursor.skip((page-1)*per_page).limit(per_page))

    total_patients = collection.count_documents({})

    return render_template(
        "patients.html",
        patients=patients,
        total_patients=total_patients,
    )

@app.route("/patients/<patient_id>")
@login_required
def patient_detail(patient_id):
    """View details for a specific patient"""
    # Validate ObjectID
    obj_id = validate_object_id(patient_id)
    if not obj_id:
        flash("Invalid patient ID format", "danger")
        return redirect(url_for("list_patients"))

    collection = mongo.db.patients
    # BUG FIX: Use obj_id instead of ObjectId(patient_id)
    patient = collection.find_one({"_id": obj_id})

    if not patient:
        flash("Patient not found", "warning")
        return redirect(url_for("list_patients"))
    
    return render_template("patient_detail.html", patient=patient)

@app.route("/patients/<patient_id>/edit", methods=["GET", "POST"])
@login_required
def edit_patient(patient_id):
    # Validate ObjectId
    obj_id = validate_object_id(patient_id)
    if not obj_id:
        flash("Invalid patient ID format.", "danger")
        return redirect(url_for("list_patients"))
    
    collection = mongo.db.patients
    patient = collection.find_one({"_id": obj_id})

    if not patient:
        flash("Patient not found", "warning")
        return redirect(url_for("list_patients"))

    if request.method == "POST":
        try:
            update = {
                "gender": request.form.get("gender"),
                "age": int(request.form.get("age") or 0),
                "hypertension": int(request.form.get("hypertension") or 0),
                "heart_disease": int(request.form.get("heart_disease") or 0),
                "ever_married": request.form.get("ever_married"),
                "work_type": request.form.get("work_type"),
                "Residence_type": request.form.get("Residence_type"),
                "avg_glucose_level": float(request.form.get("avg_glucose_level") or 0),
                "bmi": float(request.form.get("bmi") or 0),
                "smoking_status": request.form.get("smoking_status"),
                "stroke": int(request.form.get("stroke") or 0),
            }
            
            collection.update_one({"_id": obj_id}, {"$set": update})
            flash("Patient record updated successfully.", "success")
            return redirect(url_for("patient_detail", patient_id=patient_id))
        except (ValueError, TypeError) as e:
            
            flash("Invalid input data. Please check your entries.", "danger")
            app.logger.error(f"Error updating patient {patient_id}: {e}")

    return render_template("edit_patient.html", patient=patient)

@app.route("/patients/new", methods=["GET", "POST"])
@login_required
def create_patient():
    """Create a new patient record"""
    if request.method == "POST":
        try:
            # Sanitisation and type conversion
            doc = {
                "gender": request.form.get("gender"),
                "age": int(request.form.get("age") or 0),
                "hypertension": int(request.form.get("hypertension") or 0),
                "heart_disease": int(request.form.get("heart_disease") or 0),
                "ever_married": request.form.get("ever_married"),
                "work_type": request.form.get("work_type"),
                "Residence_type": request.form.get("Residence_type"),
                "avg_glucose_level": float(request.form.get("avg_glucose_level") or 0),
                "bmi": float(request.form.get("bmi") or 0),
                "smoking_status": request.form.get("smoking_status"),
                "stroke": int(request.form.get("stroke") or 0),
            }
            result = mongo.db.patients.insert_one(doc)
            flash("Patient record created successfully.", "success")
            return redirect(url_for("patient_detail", patient_id=str(result.inserted_id)))
        except (ValueError, TypeError) as e:
            flash("Invalid input data. Please check your entries.", "danger")
            app.logger.error(f"Error creating patient: {e}")
    
    
    return render_template("create_patient.html")

@app.route("/patients/<patient_id>/delete", methods=["POST"])
@login_required
def delete_patient(patient_id):
    """Delete a patient record."""
    # Validate ObjectId
    obj_id = validate_object_id(patient_id)
    if not obj_id:
        flash("Invalid patient ID format.", "danger")
        return redirect(url_for("list_patients"))
    
    try:
        result = mongo.db.patients.delete_one({"_id": obj_id})
        
        if result.deleted_count > 0:
            flash("Patient record deleted successfully.", "success")
        else:
            flash("Patient not found.", "warning")
    except Exception as e:
        flash("Error deleting patient record.", "danger")
        app.logger.error(f"Error deleting patient {patient_id}: {e}")
    
    return redirect(url_for("list_patients"))

# -----------------------
# Load CSV into MongoDB patients collection
# -----------------------

def import_csv_into_mongo():
    """Import patient CSV into MongoDB if collection is empty."""
    collection = mongo.db.patients
    if collection.count_documents({}) == 0:
        csv_path = os.path.join(basedir, "healthcare-dataset-stroke-data.csv")
        if not os.path.exists(csv_path):
            print(f"[WARN] CSV file not found at {csv_path}. Skipping import.")
            return

        df = pd.read_csv(csv_path)
        records = df.to_dict(orient="records")
        collection.insert_many(records)
        print(f"[INFO] Imported {len(records)} patient records into MongoDB.")
    else:
        print("[INFO] Patients collection already populated; skipping CSV import.")


# Run & create tables
# -----------------------
if __name__ == "__main__":
    with app.app_context():
        db.create_all()  # ensure auth.db and User table exist
        import_csv_into_mongo()
    
    print("=" * 70)
    print("FLASK APP STARTING")
    print("=" * 70)
    print(f"SECRET_KEY: {app.config['SECRET_KEY'][:20]}...")
    print(f"SESSION_COOKIE_SECURE: {app.config['SESSION_COOKIE_SECURE']}")
    print(f"SESSION_PERMANENT: {app.config['SESSION_PERMANENT']}")
    print("=" * 70)
    
    app.run(debug=True)