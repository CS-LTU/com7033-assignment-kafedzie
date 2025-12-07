import os
import pandas as pd
from dotenv import load_dotenv
from bson import ObjectId
from bson.errors import InvalidId

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
app.config["SESSION_COOKIE_SECURE"] = True

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


# -----------------------
# Patient Management Routes

@app.route("/")
def home():
    return render_template("home.html")

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
    if smoking:
        query["smoking_status"] = smoking

    collection = mongo.db.patients

    patients_cursor = collection.find(query).sort("_id", -1)  # newest first
    page = request.args.get('page', 1, type=int)
    per_page = 20
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
    #Validate ObjectID
    obj_id = validate_object_id(patient_id)
    if not obj_id:
        flash("Invalid patient ID format", "danger")
        return redirect(url_for("list_patients"))

    collection = mongo.db.patients
    patient = collection.find_one({"_id": ObjectId(patient_id)})

    if not patient:
        return ("Patient not found", "warning")
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
    patient = collection.find_one({"_id": ObjectId(patient_id)})

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
            collection.update_one({"_id": ObjectId(patient_id)}, {"$set": update})
            flash("Patient record updated successfully.", "success")
            return redirect(url_for("patient_detail", patient_id=patient_id))
        except (ValueError, TypeError) as e:
            flash(("Invalid input data. Please check your entries.", "danger"))
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
            flash("Patient record created successfully.", "succes")
            return redirect(url_for("patient_detail", patient_id=str(result.inserted.id)))
        except (ValueError, TypeError) as e:
            flash("Invalid input data. Please check your entries.", "danger")
            app.logger.error(f"Error creating patient: {e}")
    return render_template("create_patient.html")


    # GET → show the form
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
# Authentication routes
# -----------------------

@app.route("/register", methods=["GET", "POST"])
def register():
    #User Registration Page
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
    #User Login page
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
    app.run(debug=True)
