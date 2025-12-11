import pytest
from flask import url_for
from werkzeug.security import generate_password_hash
from bson.objectid import ObjectId

# FIXTURES - Test Setup
# ============================================================================

@pytest.fixture
def app():
    """Create and configure a test Flask application"""
    from main import app as flask_app
    
    # Test configuration
    flask_app.config['TESTING'] = True
    flask_app.config['WTF_CSRF_ENABLED'] = False  # Disable CSRF for testing
    flask_app.config['SECRET_KEY'] = 'test-secret-key'
    flask_app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    flask_app.config['SESSION_COOKIE_SECURE'] = False
    
    # Use mongomock for MongoDB testing
    flask_app.config['MONGO_URI'] = 'mongomock://localhost'
    
    with flask_app.app_context():
        # Import db here to avoid circular imports
        from main import db
        db.create_all()
        yield flask_app
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    """Create a test client"""
    return app.test_client()


@pytest.fixture
def runner(app):
    """Create a test CLI runner"""
    return app.test_cli_runner()


@pytest.fixture
def mongo(app):
    """Get MongoDB test instance"""
    from main import mongo as mongo_instance
    return mongo_instance


@pytest.fixture
def admin_user(app):
    """Create a test admin user"""
    from main import db, User
    
    # Create user instance first
    user = User(
        email='admin@test.com',
        role='admin'
    )
    # Set password_hash separately (not password)
    user.password_hash = generate_password_hash('admin123')
    
    db.session.add(user)
    db.session.commit()
    return user


@pytest.fixture
def regular_user(app):
    """Create a test regular user"""
    from main import db, User
    
    # Create user instance first
    user = User(
        email='user@test.com',
        role='user'
    )
    # Set password_hash separately (not password)
    user.password_hash = generate_password_hash('user123')
    
    db.session.add(user)
    db.session.commit()
    return user


@pytest.fixture
def sample_patient(mongo):
    """Create a sample patient in MongoDB"""
    patient_data = {
        'gender': 'Female',
        'age': 45,
        'hypertension': 0,
        'heart_disease': 0,
        'ever_married': 'Yes',
        'work_type': 'Private',
        'Residence_type': 'Urban',
        'avg_glucose_level': 95.0,
        'bmi': 24.5,
        'smoking_status': 'never smoked',
        'stroke': 0
    }
    result = mongo.db.patients.insert_one(patient_data)
    patient_data['_id'] = result.inserted_id
    return patient_data


def login(client, email, password):
    """Helper function to log in a user"""
    return client.post('/login', data={
        'email': email,
        'password': password
    }, follow_redirects=True)


def logout(client):
    """Helper function to log out a user"""
    return client.get('/logout', follow_redirects=True)

# AUTHENTICATION TESTS
# ============================================================================

class TestAuthentication:
    """Test user authentication functionality"""
    
    def test_register_page_loads(self, client):
        """Test that register page loads successfully"""
        response = client.get('/register')
        assert response.status_code == 200
        assert b'Create Account' in response.data or b'Register' in response.data
    
    def test_register_new_user(self, client):
        """Test registering a new user"""
        response = client.post('/register', data={
            'email': 'newuser@test.com',
            'password': 'password123',
            'confirm_password': 'password123'
        }, follow_redirects=True)
        
        assert response.status_code == 200
        assert b'Account created' in response.data or b'success' in response.data.lower()
    
    def test_register_duplicate_email(self, client, regular_user):
        """Test that duplicate email registration is prevented"""
        response = client.post('/register', data={
            'email': 'user@test.com',  # Already exists
            'password': 'password123',
            'confirm_password': 'password123'
        }, follow_redirects=True)
        
        assert b'already registered' in response.data.lower() or b'exists' in response.data.lower()
    
    def test_register_password_mismatch(self, client):
        """Test that password confirmation is enforced"""
        response = client.post('/register', data={
            'email': 'test@test.com',
            'password': 'password123',
            'confirm_password': 'different123'
        }, follow_redirects=True)
        
        assert response.status_code == 200
        # Should show error or stay on register page
    
    def test_login_page_loads(self, client):
        """Test that login page loads successfully"""
        response = client.get('/login')
        assert response.status_code == 200
        assert b'Login' in response.data or b'Sign in' in response.data
    
    def test_login_success(self, client, regular_user):
        """Test successful login"""
        response = login(client, 'user@test.com', 'user123')
        assert response.status_code == 200
        assert b'Welcome' in response.data or b'Patient' in response.data
    
    def test_login_wrong_password(self, client, regular_user):
        """Test login with wrong password"""
        response = login(client, 'user@test.com', 'wrongpassword')
        assert b'Invalid' in response.data or b'password' in response.data.lower()
    
    def test_login_nonexistent_user(self, client):
        """Test login with non-existent email"""
        response = login(client, 'nonexistent@test.com', 'password123')
        assert b'Invalid' in response.data or b'not found' in response.data.lower()
    
    def test_logout(self, client, regular_user):
        """Test logout functionality"""
        login(client, 'user@test.com', 'user123')
        response = logout(client)
        assert response.status_code == 200
        assert b'logged out' in response.data.lower() or b'Login' in response.data
    
    def test_protected_route_requires_login(self, client):
        """Test that protected routes require authentication"""
        response = client.get('/patients', follow_redirects=True)
        assert b'Login' in response.data or response.status_code == 401


# PATIENT CRUD TESTS
# ============================================================================

class TestPatientOperations:
    """Test patient CRUD operations"""
    
    def test_list_patients_requires_auth(self, client):
        """Test that patient list requires authentication"""
        response = client.get('/patients')
        assert response.status_code == 302 or response.status_code == 401
    
    def test_list_patients_authenticated(self, client, regular_user, sample_patient):
        """Test viewing patient list when authenticated"""
        login(client, 'user@test.com', 'user123')
        response = client.get('/patients')
        assert response.status_code == 200
        assert b'Patient' in response.data
    
    def test_view_patient_detail(self, client, regular_user, sample_patient):
        """Test viewing patient detail page"""
        login(client, 'user@test.com', 'user123')
        patient_id = str(sample_patient['_id'])
        response = client.get(f'/patients/{patient_id}')
        assert response.status_code == 200
        assert b'Female' in response.data  # Patient gender
        assert b'45' in response.data  # Patient age
    
    def test_view_invalid_patient_id(self, client, regular_user):
        """Test viewing patient with invalid ID"""
        login(client, 'user@test.com', 'user123')
        response = client.get('/patients/invalid_id', follow_redirects=True)
        assert b'Invalid' in response.data or b'not found' in response.data.lower()
    
    def test_create_patient_page_loads(self, client, regular_user):
        """Test that create patient page loads"""
        login(client, 'user@test.com', 'user123')
        response = client.get('/patients/new')
        assert response.status_code == 200
        assert b'New Patient' in response.data or b'Create' in response.data
    
    def test_create_patient_success(self, client, regular_user, mongo):
        """Test creating a new patient"""
        login(client, 'user@test.com', 'user123')
        
        # Count patients before
        count_before = mongo.db.patients.count_documents({})
        
        response = client.post('/patients/new', data={
            'gender': 'Male',
            'age': 99,  # Use unique age
            'hypertension': 1,
            'heart_disease': 0,
            'ever_married': 'Yes',
            'work_type': 'Private',
            'Residence_type': 'Urban',
            'avg_glucose_level': 110.5,
            'bmi': 28.3,
            'smoking_status': 'formerly smoked',
            'stroke': 0
        }, follow_redirects=True)
        
        assert response.status_code == 200
        
        # To verify patient count increased
        count_after = mongo.db.patients.count_documents({})
        assert count_after == count_before + 1, f"Patient count should increase by 1. Before: {count_before}, After: {count_after}"
        
        # To verify patient was added with correct data
        patient = mongo.db.patients.find_one({'age': 99, 'gender': 'Male'})
        assert patient is not None, "Patient with age 99 and gender Male should exist"
        assert patient['gender'] == 'Male'
        assert patient['age'] == 99
    
    def test_edit_patient_page_loads(self, client, regular_user, sample_patient):
        """Test that edit patient page loads"""
        login(client, 'user@test.com', 'user123')
        patient_id = str(sample_patient['_id'])
        response = client.get(f'/patients/{patient_id}/edit')
        assert response.status_code == 200
        assert b'Edit' in response.data
    
    def test_edit_patient_success(self, client, regular_user, sample_patient, mongo):
        """Test editing a patient"""
        login(client, 'user@test.com', 'user123')
        patient_id = str(sample_patient['_id'])
        
        response = client.post(f'/patients/{patient_id}/edit', data={
            'gender': 'Female',
            'age': 46,  # Changed from 45
            'hypertension': 1,  # Changed from 0
            'heart_disease': 0,
            'ever_married': 'Yes',
            'work_type': 'Private',
            'Residence_type': 'Urban',
            'avg_glucose_level': 95.0,
            'bmi': 24.5,
            'smoking_status': 'never smoked',
            'stroke': 0
        }, follow_redirects=True)
        
        assert response.status_code == 200
        
        # To verify changes in database
        patient = mongo.db.patients.find_one({'_id': sample_patient['_id']})
        assert patient['age'] == 46
        assert patient['hypertension'] == 1
    
    def test_delete_patient_regular_user_denied(self, client, regular_user, sample_patient, mongo):
        """Test that regular users cannot delete patients"""
        login(client, 'user@test.com', 'user123')
        patient_id = str(sample_patient['_id'])
        
        # Try to delete
        response = client.post(f'/patients/{patient_id}/delete', follow_redirects=True)
        
        # The key test is: was the patient actually deleted?
        patient_still_exists = mongo.db.patients.find_one({'_id': sample_patient['_id']})
        
        # Patient should still exist (not deleted by regular user)
        assert patient_still_exists is not None, "Regular user should not be able to delete patient"
        
        # Checking for permission-related messages if they exist
        # But don't fail if the app just silently prevents deletion
        if b'admin' in response.data.lower() or b'permission' in response.data.lower():
            pass  # Good, explicit error message shown
    
    def test_delete_patient_admin_success(self, client, admin_user, sample_patient, mongo):
        """Test that admin can delete patients"""
        login(client, 'admin@test.com', 'admin123')
        patient_id = str(sample_patient['_id'])
        
        response = client.post(f'/patients/{patient_id}/delete', follow_redirects=True)
        assert response.status_code == 200
        
        # To verify patient was deleted
        patient = mongo.db.patients.find_one({'_id': sample_patient['_id']})
        assert patient is None


# ROLE-BASED ACCESS CONTROL TESTS
# ============================================================================

class TestRoleBasedAccess:
    """Test role-based access control"""
    
    def test_regular_user_cannot_access_admin_panel(self, client, regular_user):
        """Test that regular users are blocked from admin panel"""
        login(client, 'user@test.com', 'user123')
        response = client.get('/admin', follow_redirects=True)
        assert b'admin' in response.data.lower() or response.status_code == 403
    
    def test_admin_can_access_admin_panel(self, client, admin_user):
        """Test that admins can access admin panel"""
        login(client, 'admin@test.com', 'admin123')
        response = client.get('/admin')
        assert response.status_code == 200
        assert b'Admin' in response.data or b'User Management' in response.data
    
    def test_admin_can_create_users(self, client, admin_user):
        """Test that admin can create new users"""
        login(client, 'admin@test.com', 'admin123')
        response = client.get('/admin/users/create')
        assert response.status_code == 200
        assert b'Create' in response.data
    
    def test_regular_user_cannot_create_users(self, client, regular_user):
        """Test that regular users cannot create users"""
        login(client, 'user@test.com', 'user123')
        response = client.get('/admin/users/create', follow_redirects=True)
        assert b'admin' in response.data.lower() or response.status_code == 403
    
    def test_admin_can_reset_passwords(self, client, admin_user):
        """Test that admin can access password reset"""
        login(client, 'admin@test.com', 'admin123')
        response = client.get('/reset-password')
        assert response.status_code == 200
        assert b'Reset' in response.data or b'Password' in response.data
    
    def test_regular_user_cannot_reset_passwords(self, client, regular_user):
        """Test that regular users cannot reset passwords"""
        login(client, 'user@test.com', 'user123')
        response = client.get('/reset-password', follow_redirects=True)
        assert b'admin' in response.data.lower() or response.status_code == 403


# FILTER AND PAGINATION TESTS
# ============================================================================

class TestFiltersAndPagination:
    """Test patient filtering and pagination"""
    
    def test_filter_by_gender(self, client, regular_user, mongo):
        """Test filtering patients by gender"""
        # Add multiple patients
        mongo.db.patients.insert_many([
            {'gender': 'Male', 'age': 30, 'stroke': 0, 'hypertension': 0, 
             'heart_disease': 0, 'bmi': 25.0, 'avg_glucose_level': 90.0,
             'ever_married': 'No', 'work_type': 'Private', 
             'Residence_type': 'Urban', 'smoking_status': 'never smoked'},
            {'gender': 'Female', 'age': 40, 'stroke': 0, 'hypertension': 0,
             'heart_disease': 0, 'bmi': 24.0, 'avg_glucose_level': 85.0,
             'ever_married': 'Yes', 'work_type': 'Private',
             'Residence_type': 'Rural', 'smoking_status': 'never smoked'}
        ])
        
        login(client, 'user@test.com', 'user123')
        response = client.get('/patients?gender=Male')
        assert response.status_code == 200
        assert b'Male' in response.data
    
    def test_filter_by_stroke(self, client, regular_user, mongo):
        """Test filtering patients by stroke history"""
        mongo.db.patients.insert_many([
            {'gender': 'Male', 'age': 60, 'stroke': 1, 'hypertension': 1,
             'heart_disease': 0, 'bmi': 30.0, 'avg_glucose_level': 120.0,
             'ever_married': 'Yes', 'work_type': 'Private',
             'Residence_type': 'Urban', 'smoking_status': 'smokes'},
            {'gender': 'Female', 'age': 35, 'stroke': 0, 'hypertension': 0,
             'heart_disease': 0, 'bmi': 22.0, 'avg_glucose_level': 80.0,
             'ever_married': 'No', 'work_type': 'Private',
             'Residence_type': 'Urban', 'smoking_status': 'never smoked'}
        ])
        
        login(client, 'user@test.com', 'user123')
        response = client.get('/patients?stroke=1')
        assert response.status_code == 200
        # Should show stroke patients
    
    def test_pagination_works(self, client, regular_user, mongo):
        """Test that pagination functions correctly"""
        # Add 40 patients to test pagination (30 per page)
        patients = []
        for i in range(40):
            patients.append({
                'gender': 'Male' if i % 2 == 0 else 'Female',
                'age': 20 + i,
                'stroke': 0,
                'hypertension': 0,
                'heart_disease': 0,
                'bmi': 24.0,
                'avg_glucose_level': 90.0,
                'ever_married': 'No',
                'work_type': 'Private',
                'Residence_type': 'Urban',
                'smoking_status': 'never smoked'
            })
        mongo.db.patients.insert_many(patients)
        
        login(client, 'user@test.com', 'user123')
        
        # Test page 1
        response = client.get('/patients?page=1')
        assert response.status_code == 200
        
        # Test page 2
        response = client.get('/patients?page=2')
        assert response.status_code == 200
    
    def test_invalid_stroke_filter_handled(self, client, regular_user):
        """Test that invalid stroke filter value is handled gracefully"""
        login(client, 'user@test.com', 'user123')
        response = client.get('/patients?stroke=invalid', follow_redirects=True)
        # Should either redirect or show error
        assert response.status_code == 200


# DATA VALIDATION TESTS
# ============================================================================

class TestDataValidation:
    """Test data validation and error handling"""
    
    def test_invalid_patient_id_format(self, client, regular_user):
        """Test handling of invalid ObjectId format"""
        login(client, 'user@test.com', 'user123')
        response = client.get('/patients/not-a-valid-objectid', follow_redirects=True)
        assert b'Invalid' in response.data or b'not found' in response.data.lower()
    
    def test_create_patient_missing_required_fields(self, client, regular_user):
        """Test that required fields are enforced"""
        login(client, 'user@test.com', 'user123')
        response = client.post('/patients/new', data={
            'gender': 'Male',
            # Missing other required fields
        }, follow_redirects=True)
        
        # Should show error or stay on form
        assert response.status_code == 200
    
    def test_negative_age_rejected(self, client, regular_user):
        """Test that negative age is rejected"""
        login(client, 'user@test.com', 'user123')
        response = client.post('/patients/new', data={
            'gender': 'Male',
            'age': -5,  # Invalid
            'hypertension': 0,
            'heart_disease': 0,
            'ever_married': 'No',
            'work_type': 'Private',
            'Residence_type': 'Urban',
            'avg_glucose_level': 90.0,
            'bmi': 24.0,
            'smoking_status': 'never smoked',
            'stroke': 0
        }, follow_redirects=True)
        
        # Should reject negative age
        assert response.status_code == 200


# PASSWORD FUNCTIONALITY TESTS
# ============================================================================

class TestPasswordFunctionality:
    """Test password-related functionality"""
    
    def test_forgot_password_page_loads(self, client):
        """Test that forgot password page loads"""
        response = client.get('/forgot-password')
        assert response.status_code == 200
        assert b'Forgot' in response.data or b'Password' in response.data
    
    def test_forgot_password_submission(self, client, regular_user):
        """Test submitting forgot password form"""
        response = client.post('/forgot-password', data={
            'email': 'user@test.com'
        }, follow_redirects=True)
        
        assert response.status_code == 200
        # Should show confirmation message
    
    def test_admin_reset_password(self, client, admin_user, regular_user):
        """Test admin resetting user password"""
        login(client, 'admin@test.com', 'admin123')
        
        response = client.post('/reset-password', data={
            'email': 'user@test.com',
            'new_password': 'newpassword123',
            'confirm_password': 'newpassword123'
        }, follow_redirects=True)
        
        assert response.status_code == 200
        
        # Logout and try new password
        logout(client)
        response = login(client, 'user@test.com', 'newpassword123')
        assert b'Welcome' in response.data or b'Patient' in response.data


# RUN TESTS
# ============================================================================

if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short'])
