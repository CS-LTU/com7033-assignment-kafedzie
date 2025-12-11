# com7033-assignment-kafedzie

🏥 Flask Patient Management System

A secure healthcare records dashboard using Flask, SQLite (Auth), MongoDB (Patients), and Role-Based Access Control (RBAC).

🚀 Overview

This application is a secure web-based Patient Management System built using:

Flask (backend framework)

SQLite (user authentication database)

MongoDB (patient health records)

WTForms + CSRFProtect (secure forms)

Flask-Login (session handling & authentication)

Role-Based Access Control (RBAC) (Admin vs. General Users)

The application supports:

✔ User registration & login
✔ Admin capabilities (create users, delete users, modify roles)
✔ Secure session handling
✔ Password hashing (PBKDF2-SHA256)
✔ Create / View / Edit / Delete patient records
✔ Pagination & filtering
✔ Automatic CSV import of patient data into MongoDB

==> System Architecture

🔹 SQLite (Authentication Layer)

Stores user accounts, hashed passwords, roles (admin/user), timestamps.

🔹 MongoDB (Patients Collection)

Stores patient medical records including:

Gender

Age

Hypertension

Heart disease

Glucose/BMI

Smoking status

Stroke outcome

🔹 Flask Application

Handles:

Login & registration workflows

Admin panel

CRUD operations for patients

CSRF-protected form handling

Pagination & filtering

🔑 User Roles
👤 Standard User

View patients

Edit / Create / Delete patients

👑 Administrator

All user permissions PLUS:

Create users

Delete users

Change roles

Reset passwords

==> Technologies Used

| Component        | Technology        |
| ---------------- | ----------------- |
| Backend          | Flask             |
| Auth Database    | SQLite            |
| Patient Database | MongoDB           |
| ORM              | SQLAlchemy        |
| Forms            | Flask-WTF         |
| Hashing          | Werkzeug security |
| Sessions         | Flask-Login       |
| Import           | Pandas CSV loader |

==> 🔒 Security Rationale

This application intentionally implements several robust security measures suitable for healthcare-related data systems:

✔ Avoids plaintext passwords

All passwords are hashed with PBKDF2-SHA256, protecting against dictionary & rainbow-table attacks.

✔ CSRF Protection

Every form is protected by tokens, preventing cross-site request forgery.

✔ Strict session handling

Cookies are HttpOnly

SameSite=Lax prevents cross-site hijacking

Session expires after 24 hours

✔ RBAC ensures least privilege

General users cannot modify accounts; admins control system-level actions.

✔ ObjectId validation prevents MongoDB injection

All patient ID inputs are checked with safe constructors.

| Feature         | Description                                          |
| --------------- | ---------------------------------------------------- |
| Authentication  | Login, logout, registration, secure password hashing |
| RBAC            | Admin vs user privileges enforced with decorators    |
| Data Security   | CSRF, secure cookies, sanitisation, validation       |
| Data Separation | SQLite for auth, MongoDB for patients                |
| CRUD Operations | Create, edit, delete, view patients                  |
| Pagination      | Efficient navigation through large datasets          |
| Filtering       | Filter by gender, stroke, smoking status             |
| CSV Import      | Loads dataset into MongoDB automatically             |

==> Directory

COM7033/
│
├── main.py # Main Flask application
├── auth.db # SQLite authentication DB (auto-created)
├── requirements.txt
├── test_app.py #Test application
├── test_requirements.txt  
├── templates/ # HTML templates
│ ├── home.html
│ ├── login.html
│ ├── register.html
│ ├── patients.html
│ ├── patient_detail.html
│ ├── edit_patient.html
│ ├── create_patient.html
│ ├── admin_panel.html
│ ├── admin_create_user.html
│ └── reset_password.html
│
├── static/ # CSS, JS
│
└── healthcare-dataset-stroke-data.csv

🤝 Contributing

This is an academic project for COM7033 Secure Software Development module.

📝 License

This project is developed for educational purposes as part of the COM7033 module at Leeds Trinity University.

👥 Author

- Student Name: Nana Kodwo Bentsi Afedzie
- Student ID: 2414012
- Module: COM7033 - Secure Software Development
- Academic Year: 2025-2026

📧 Support

For issues or questions:

- Module Leader: x.lu@leedstrinity.ac.uk
- Assessment Team: assessment@leedstrinity.ac.uk

🙏 Acknowledgments

- Dataset: Kaggle Stroke Prediction Dataset
- Framework: Flask Documentation
- Security: OWASP Security Guidelines
- Database: MongoDB Documentation
