import os
import logging
import cv2
import numpy as np
from flask import Flask, request, render_template, jsonify, flash, redirect, url_for, session, send_from_directory, abort
import uuid
from datetime import datetime
from werkzeug.utils import secure_filename
from urllib.parse import urlparse as url_parse
from util.face_util import detect_faces, get_face_encoding, compare_faces
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from functools import wraps
from models import db, User, AuditLog, Role, Sector, Permission, RolePermission, UserSector
from models import JusticeRecord, BankingRecord, HumanitarianRecord, VotingRecord, IdCardRecord, TransportationRecord

# Configure logging
logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "facial-recognition-secret-key")

# Configure the database
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "sqlite:///facial_recognition.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}

# Initialize the database
db.init_app(app)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'info'

# User loader for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Create upload directory if it doesn't exist
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB limit

# Allowed file extensions
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}

# Role-based access control decorator
def role_required(role_name):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                return redirect(url_for('login'))
            
            # Get the user's role
            role = Role.query.get(current_user.role_id)
            if not role or role.name != role_name:
                flash(f'You need {role_name} permissions to access this page.', 'danger')
                return redirect(url_for('index'))
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Permission-based access control decorator
def permission_required(permission_name):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                return redirect(url_for('login'))
            
            # Check if user has the required permission
            if not current_user.has_permission(permission_name):
                flash(f'You do not have permission to access this feature.', 'danger')
                return redirect(url_for('index'))
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Sector access control decorator
def sector_access_required(sector_name):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                return redirect(url_for('login'))
            
            # Check if user has access to the required sector
            if not current_user.has_sector_access(sector_name):
                flash(f'You do not have access to the {sector_name} sector.', 'danger')
                return redirect(url_for('index'))
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Create database tables
with app.app_context():
    db.create_all()
    
    # Create default roles if they don't exist
    if not Role.query.filter_by(name='Agency Admin').first():
        admin_role = Role(name='Agency Admin', description='Full access to all data and management options within their sector')
        db.session.add(admin_role)
        
    if not Role.query.filter_by(name='Agency User').first():
        user_role = Role(name='Agency User', description='Limited access to view, add, update, and delete relevant user data based on their sector')
        db.session.add(user_role)
        
    if not Role.query.filter_by(name='Viewer').first():
        viewer_role = Role(name='Viewer', description='Read-only access to observe data without ability to make modifications')
        db.session.add(viewer_role)
    
    # Create default sectors if they don't exist
    default_sectors = ['Justice', 'Banking', 'Humanitarian', 'Voting', 'ID Card', 'Transportation']
    for sector_name in default_sectors:
        if not Sector.query.filter_by(name=sector_name).first():
            sector = Sector(name=sector_name, description=f'{sector_name} sector module')
            db.session.add(sector)
    
    # Create default permissions if they don't exist
    default_permissions = [
        ('create_user', 'Create new user records'),
        ('view_user', 'View user records'),
        ('edit_user', 'Edit user records'),
        ('delete_user', 'Delete user records'),
        ('reset_database', 'Reset the entire database'),
        ('manage_roles', 'Assign and manage user roles'),
        ('view_audit_logs', 'View system audit logs'),
        ('view_statistics', 'View system statistics'),
    ]
    
    for perm_name, perm_desc in default_permissions:
        if not Permission.query.filter_by(name=perm_name).first():
            permission = Permission(name=perm_name, description=perm_desc)
            db.session.add(permission)
    
    db.session.commit()
    
    # Assign permissions to roles
    admin_role = Role.query.filter_by(name='Agency Admin').first()
    user_role = Role.query.filter_by(name='Agency User').first()
    viewer_role = Role.query.filter_by(name='Viewer').first()
    
    # Admin has all permissions
    if admin_role:
        for permission in Permission.query.all():
            if not RolePermission.query.filter_by(role_id=admin_role.id, permission_id=permission.id).first():
                role_perm = RolePermission(role_id=admin_role.id, permission_id=permission.id)
                db.session.add(role_perm)
    
    # Agency User has limited permissions
    if user_role:
        user_permissions = ['create_user', 'view_user', 'edit_user', 'view_statistics']
        for perm_name in user_permissions:
            permission = Permission.query.filter_by(name=perm_name).first()
            if permission and not RolePermission.query.filter_by(role_id=user_role.id, permission_id=permission.id).first():
                role_perm = RolePermission(role_id=user_role.id, permission_id=permission.id)
                db.session.add(role_perm)
    
    # Viewer has only view permissions
    if viewer_role:
        viewer_permissions = ['view_user']
        for perm_name in viewer_permissions:
            permission = Permission.query.filter_by(name=perm_name).first()
            if permission and not RolePermission.query.filter_by(role_id=viewer_role.id, permission_id=permission.id).first():
                role_perm = RolePermission(role_id=viewer_role.id, permission_id=permission.id)
                db.session.add(role_perm)
    
    db.session.commit()

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def log_audit(user_id, action, status, details=None, ip_address=None):
    """Record an audit log entry"""
    try:
        audit_log = AuditLog(
            user_id=user_id,
            action=action,
            status=status,
            details=details,
            ip_address=ip_address,
            device_info=request.user_agent.string if request.user_agent else None
        )
        db.session.add(audit_log)
        db.session.commit()
    except Exception as e:
        logging.error(f"Error logging audit: {e}")
        db.session.rollback()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['POST'])
def register():
    if 'image' not in request.files:
        return jsonify({'success': False, 'message': 'No image file provided'}), 400
    
    # Extract basic user information
    file = request.files['image']
    data = request.form
    full_name = data.get('full_name', '').strip()
    email = data.get('email', '').strip()
    dob_str = data.get('dob', '').strip()
    gender = data.get('gender', '').strip()
    nationality = data.get('nationality', '').strip()
    phone_number = data.get('phone_number', '').strip()
    address = data.get('address', '').strip()
    
    # RBAC specific parameters
    username = data.get('username', '').strip()
    password = data.get('password', '').strip()
    role_name = data.get('role', 'Viewer').strip()  # Default to Viewer if no role specified
    sectors = data.getlist('sectors')  # List of sectors this user has access to
    # Convert string values to boolean
    has_biometric_consent_val = data.get('has_biometric_consent', 'false')
    has_data_storage_consent_val = data.get('has_data_storage_consent', 'false')
    terms_accepted_val = data.get('terms_accepted', 'false')
    
    # Debug logging
    logging.debug(f"Biometric consent value: {has_biometric_consent_val}")
    logging.debug(f"Data storage consent value: {has_data_storage_consent_val}")
    logging.debug(f"Terms accepted value: {terms_accepted_val}")
    
    # Allow both 'true' (lowercase) and 'True' (uppercase)
    has_biometric_consent = has_biometric_consent_val.lower() == 'true' or has_biometric_consent_val == 'on'
    has_data_storage_consent = has_data_storage_consent_val.lower() == 'true' or has_data_storage_consent_val == 'on'
    terms_accepted = terms_accepted_val.lower() == 'true' or terms_accepted_val == 'on'
    
    # Validate required fields
    if not full_name:
        return jsonify({'success': False, 'message': 'Full name is required'}), 400
    
    if not has_biometric_consent or not has_data_storage_consent or not terms_accepted:
        return jsonify({'success': False, 'message': 'All consent checkboxes must be accepted'}), 400
    
    if file.filename == '':
        return jsonify({'success': False, 'message': 'No image selected'}), 400
    
    if not allowed_file(file.filename):
        return jsonify({'success': False, 'message': 'Invalid file type. Only PNG, JPG, and JPEG are allowed'}), 400
    
    # Parse DOB if provided
    dob = None
    if dob_str:
        try:
            dob = datetime.strptime(dob_str, '%Y-%m-%d').date()
        except ValueError:
            return jsonify({'success': False, 'message': 'Invalid date format for Date of Birth. Use YYYY-MM-DD'}), 400
    
    # Save the uploaded file with a secure filename
    filename = secure_filename(file.filename)
    unique_id = str(uuid.uuid4())
    unique_filename = f"{unique_id}_{filename}"
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
    file.save(file_path)
    
    # Detect faces in the image
    faces = detect_faces(file_path)
    
    if len(faces) == 0:
        os.remove(file_path)  # Clean up the file if no face is detected
        return jsonify({'success': False, 'message': 'No face detected in the image'}), 400
    
    if len(faces) > 1:
        os.remove(file_path)  # Clean up the file if multiple faces are detected
        return jsonify({'success': False, 'message': 'Multiple faces detected. Please upload an image with a single face'}), 400
    
    # Get face encoding
    face_encoding = get_face_encoding(file_path)
    
    if face_encoding is None:
        os.remove(file_path)  # Clean up the file if encoding fails
        return jsonify({'success': False, 'message': 'Failed to encode face. Please try again with a clearer image'}), 400
    
    try:
        # Check if user with this email already exists
        if email and User.query.filter_by(email=email).first():
            os.remove(file_path)
            return jsonify({'success': False, 'message': 'A user with this email already exists'}), 400
            
        # Check if username already exists (if provided)
        if username and User.query.filter_by(username=username).first():
            os.remove(file_path)
            return jsonify({'success': False, 'message': f'Username {username} is already taken'}), 400
            
        # For RBAC, check if a username and password were provided 
        if not username and not password:
            # If neither is provided, this might be a frontend form without RBAC fields yet
            # We can auto-generate a username and a simple password
            username = f"user_{full_name.lower().replace(' ', '_')}"
            password = str(uuid.uuid4())[:8]  # Generate a simple 8-character password
            logging.warning(f"Auto-generated username ({username}) and password for user without login credentials")
        
        # Get the role object
        role = Role.query.filter_by(name=role_name).first()
        if not role:
            # Default to Viewer if the specified role doesn't exist
            role = Role.query.filter_by(name='Viewer').first()
            
        # Create new user
        new_user = User(
            user_id=unique_id,
            username=username,
            full_name=full_name,
            dob=dob,
            gender=gender,
            nationality=nationality,
            email=email,
            phone_number=phone_number,
            address=address,
            image_path=file_path,
            has_biometric_consent=has_biometric_consent,
            has_data_storage_consent=has_data_storage_consent,
            terms_accepted=terms_accepted,
            ip_address=request.remote_addr,
            device_type=request.user_agent.platform if request.user_agent else None,
            role_id=role.id if role else None,
            is_active=True
        )
        
        # Set password if provided
        if password:
            new_user.set_password(password)
            
        # Set the facial encoding
        new_user.set_facial_embedding(face_encoding)
        
        # Save to database
        db.session.add(new_user)
        db.session.commit()
        
        # Add sector associations
        if sectors:
            for sector_name in sectors:
                sector = Sector.query.filter_by(name=sector_name).first()
                if sector:
                    user_sector = UserSector(user_id=new_user.id, sector_id=sector.id)
                    db.session.add(user_sector)
            
            db.session.commit()
        
        # Log the registration with role information
        log_audit(new_user.id, 'register', 'success', 
                f"User {full_name} registered with role {role_name if role else 'None'}", 
                request.remote_addr)
        
        logging.debug(f"Registered user: {full_name} with role {role_name if role else 'None'}")
        
        # Return RBAC information along with user details
        return jsonify({
            'success': True, 
            'message': f'User {full_name} registered successfully!',
            'user_id': unique_id,
            'username': username,
            'role': role_name if role else 'None',
            'sectors': sectors
        }), 200
        
    except Exception as e:
        db.session.rollback()
        os.remove(file_path)  # Clean up on error
        logging.error(f"Error registering user: {e}")
        return jsonify({'success': False, 'message': 'Database error occurred during registration'}), 500

@app.route('/identify', methods=['POST'])
def identify():
    if 'image' not in request.files:
        return jsonify({'success': False, 'message': 'No image file provided'}), 400
    
    file = request.files['image']
    
    if file.filename == '':
        return jsonify({'success': False, 'message': 'No image selected'}), 400
    
    if not allowed_file(file.filename):
        return jsonify({'success': False, 'message': 'Invalid file type. Only PNG, JPG, and JPEG are allowed'}), 400
    
    # Save the uploaded file
    filename = secure_filename(file.filename)
    unique_filename = f"{uuid.uuid4()}_{filename}"
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
    file.save(file_path)
    
    # Detect faces in the image
    faces = detect_faces(file_path)
    
    if len(faces) == 0:
        os.remove(file_path)  # Clean up
        return jsonify({'success': False, 'message': 'No face detected in the image'}), 400
    
    if len(faces) > 1:
        os.remove(file_path)  # Clean up
        return jsonify({'success': False, 'message': 'Multiple faces detected. Please upload an image with a single face'}), 400
    
    # Get face encoding
    face_encoding = get_face_encoding(file_path)
    
    if face_encoding is None:
        os.remove(file_path)  # Clean up
        return jsonify({'success': False, 'message': 'Failed to encode face. Please try again with a clearer image'}), 400
    
    try:
        # Get all users from database
        users = User.query.all()
        
        if not users:
            os.remove(file_path)  # Clean up
            return jsonify({'success': False, 'message': 'No registered users to compare with'}), 404
        
        # Try to find a match
        match = None
        match_confidence = 0
        
        for user in users:
            user_encoding = user.get_facial_embedding()
            # Use a threshold of 0.75 (75% similarity)
            if compare_faces(user_encoding, face_encoding, threshold=0.75):
                match = user
                # Update last identification timestamp
                user.last_identification = datetime.utcnow()
                db.session.commit()
                break
        
        # Record the identification attempt
        if match:
            log_audit(match.user_id, 'identify', 'success', 
                  f"User {match.full_name} identified", request.remote_addr)
            
            # Get user's role
            role = Role.query.get(match.role_id) if match.role_id else None
            role_name = role.name if role else "No Role Assigned"
            
            # Get sectors the user has access to
            user_sectors = UserSector.query.filter_by(user_id=match.id).all()
            sectors = []
            
            for user_sector in user_sectors:
                sector = Sector.query.get(user_sector.sector_id)
                if sector:
                    sectors.append(sector.name)
            
            # Return user data with RBAC information
            user_data = {
                'full_name': match.full_name,
                'user_id': match.user_id,
                'username': match.username,
                'role': role_name,
                'sectors': sectors,
                'is_active': match.is_active
            }
            
            os.remove(file_path)  # Clean up
            return jsonify({
                'success': True, 
                'message': f'Match found: {match.full_name}',
                'user': user_data
            }), 200
        else:
            log_audit(None, 'identify', 'failure', 
                   "No match found for identification attempt", request.remote_addr)
            
            os.remove(file_path)  # Clean up
            return jsonify({'success': False, 'message': 'No match found'}), 404
            
    except Exception as e:
        os.remove(file_path)  # Clean up
        logging.error(f"Error during identification: {e}")
        return jsonify({'success': False, 'message': 'Database error occurred during identification'}), 500

@app.route('/users', methods=['GET'])
def list_users():
    try:
        # Check if we need to include image paths (for matrix animation)
        include_images = request.args.get('include_images') == 'true'
        
        users = User.query.all()
        user_list = []
        
        for user in users:
            # Get user's role
            role = Role.query.get(user.role_id) if user.role_id else None
            role_name = role.name if role else "No Role Assigned"
            
            # Get sectors the user has access to
            user_sectors = UserSector.query.filter_by(user_id=user.id).all()
            sectors = []
            
            for user_sector in user_sectors:
                sector = Sector.query.get(user_sector.sector_id)
                if sector:
                    sectors.append(sector.name)
            
            user_data = {
                "id": user.user_id,
                "username": user.username,
                "name": user.full_name,
                "email": user.email,
                "role": role_name,
                "sectors": sectors,
                "is_active": user.is_active,
                "registration_date": user.registration_date.strftime('%Y-%m-%d %H:%M:%S') if user.registration_date else None,
                "last_login": user.last_login.strftime('%Y-%m-%d %H:%M:%S') if user.last_login else None
            }
            
            # Include image paths if requested (for matrix animation)
            if include_images and user.image_path:
                # Get the filename part of the path
                filename = os.path.basename(user.image_path)
                # Create a URL for the image using our uploaded_file route
                user_data["image_url"] = url_for('uploaded_file', filename=filename)
            
            user_list.append(user_data)
        
        return jsonify({'success': True, 'users': user_list})
    except Exception as e:
        logging.error(f"Error listing users: {e}")
        return jsonify({'success': False, 'message': 'Database error occurred while fetching users'}), 500

@app.route('/user/<user_id>', methods=['GET'])
def get_user(user_id):
    try:
        # Check if format=json is in query parameters
        if request.args.get('format') == 'json':
            user = User.query.filter_by(user_id=user_id).first()
            
            if not user:
                return jsonify({'success': False, 'message': 'User not found'}), 404
            
            # Get user's role
            role = Role.query.get(user.role_id) if user.role_id else None
            role_name = role.name if role else "No Role Assigned"
            
            # Get sectors the user has access to
            user_sectors = UserSector.query.filter_by(user_id=user.id).all()
            sectors = []
            
            for user_sector in user_sectors:
                sector = Sector.query.get(user_sector.sector_id)
                if sector:
                    sectors.append(sector.name)
                    
            user_data = {
                "id": user.user_id,
                "username": user.username,
                "full_name": user.full_name,
                "email": user.email,
                "phone_number": user.phone_number,
                "dob": user.dob.strftime('%Y-%m-%d') if user.dob else None,
                "gender": user.gender,
                "nationality": user.nationality,
                "address": user.address,
                "role": role_name,
                "sectors": sectors,
                "is_active": user.is_active,
                "registration_date": user.registration_date.strftime('%Y-%m-%d %H:%M:%S') if user.registration_date else None,
                "last_login": user.last_login.strftime('%Y-%m-%d %H:%M:%S') if user.last_login else None,
                "last_identification": user.last_identification.strftime('%Y-%m-%d %H:%M:%S') if user.last_identification else None
            }
            
            return jsonify({'success': True, 'user': user_data})
        else:
            # HTML view for user details
            user = User.query.filter_by(user_id=user_id).first()
            
            if not user:
                flash('User not found', 'danger')
                return redirect(url_for('index'))
            
            # Get user's role
            role = Role.query.get(user.role_id) if user.role_id else None
            role_name = role.name if role else "No Role Assigned"
            
            # Get sectors the user has access to
            user_sectors = UserSector.query.filter_by(user_id=user.id).all()
            sectors = []
            
            for user_sector in user_sectors:
                sector = Sector.query.get(user_sector.sector_id)
                if sector:
                    sectors.append(sector.name)
            
            # Format the date fields for display
            user_data = {
                "id": user.user_id,
                "username": user.username,
                "full_name": user.full_name,
                "email": user.email,
                "phone_number": user.phone_number,
                "dob": user.dob.strftime('%Y-%m-%d') if user.dob else None,
                "gender": user.gender,
                "nationality": user.nationality,
                "address": user.address,
                "image_path": user.image_path,
                "role": role_name,
                "sectors": sectors,
                "is_active": user.is_active,
                "registration_date": user.registration_date.strftime('%Y-%m-%d %H:%M:%S') if user.registration_date else None,
                "last_login": user.last_login.strftime('%Y-%m-%d %H:%M:%S') if user.last_login else None,
                "last_identification": user.last_identification.strftime('%Y-%m-%d %H:%M:%S') if user.last_identification else None
            }
            
            # Get activity logs for this user
            activity_logs = AuditLog.query.filter_by(user_id=user_id).order_by(AuditLog.timestamp.desc()).limit(10).all()
            
            return render_template('user_details.html', user=user_data, activity_logs=activity_logs)
            
    except Exception as e:
        logging.error(f"Error getting user: {e}")
        if request.args.get('format') == 'json':
            return jsonify({'success': False, 'message': 'Database error occurred while fetching user'}), 500
        else:
            flash('An error occurred while fetching user details', 'danger')
            return redirect(url_for('index'))

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/reset', methods=['POST'])
def reset_database():
    try:
        # Delete all users
        User.query.delete()
        # Delete all audit logs
        AuditLog.query.delete()
        
        db.session.commit()
        
        # Log the reset
        log_audit(None, 'reset_database', 'success', 
               "Database reset by administrator", request.remote_addr)
        
        return jsonify({'success': True, 'message': 'Database reset successful'})
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error resetting database: {e}")
        return jsonify({'success': False, 'message': 'Database error occurred during reset'}), 500

@app.route('/audit_logs', methods=['GET'])
def get_audit_logs():
    try:
        logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(100).all()
        
        log_list = [{
            "timestamp": log.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            "user_id": log.user_id,
            "action": log.action,
            "status": log.status,
            "details": log.details,
            "ip_address": log.ip_address
        } for log in logs]
        
        return jsonify({'success': True, 'logs': log_list})
    except Exception as e:
        logging.error(f"Error fetching audit logs: {e}")
        return jsonify({'success': False, 'message': 'Database error occurred while fetching audit logs'}), 500

# Error handlers
@app.errorhandler(413)
def request_entity_too_large(error):
    return jsonify({'success': False, 'message': 'File too large. Maximum size is 16MB'}), 413

@app.errorhandler(500)
def internal_server_error(error):
    return jsonify({'success': False, 'message': 'Internal server error'}), 500

# Authentication routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        remember = 'remember' in request.form
        
        if not username or not password:
            flash('Please provide both username and password', 'danger')
            return render_template('login.html')
        
        # First check if there's a user with this username
        user = User.query.filter_by(username=username).first()
        
        # If not found by username, try email
        if not user:
            user = User.query.filter_by(email=username).first()
        
        if user and user.check_password(password):
            # Update last login timestamp
            user.last_login = datetime.utcnow()
            db.session.commit()
            
            # Log the successful login
            log_audit(user.id, 'login', 'success', 
                   f"User {user.full_name} logged in", request.remote_addr)
            
            # Log the user in
            login_user(user, remember=remember)
            
            # Redirect to the page they were trying to access
            next_page = request.args.get('next')
            if not next_page or url_parse(next_page).netloc != '':
                next_page = url_for('dashboard')
                
            return redirect(next_page)
        else:
            # Log the failed login attempt
            log_audit(None, 'login', 'failure',
                   f"Failed login attempt for username: {username}", request.remote_addr)
                   
            flash('Invalid username or password', 'danger')
            
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    # Log the logout
    if current_user.is_authenticated:
        log_audit(current_user.id, 'logout', 'success',
               f"User {current_user.full_name} logged out", request.remote_addr)
    
    logout_user()
    flash('You have been logged out', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    # Get the user's role
    role = Role.query.get(current_user.role_id) if current_user.role_id else None
    role_name = role.name if role else "No Role Assigned"
    
    # Get sectors the user has access to
    user_sectors = UserSector.query.filter_by(user_id=current_user.id).all()
    sectors = []
    
    for user_sector in user_sectors:
        sector = Sector.query.get(user_sector.sector_id)
        if sector:
            sectors.append(sector.name)
    
    # Get audit logs for this user
    recent_logs = AuditLog.query.filter_by(user_id=current_user.id).order_by(AuditLog.timestamp.desc()).limit(5).all()
    
    return render_template('dashboard.html', 
                          user=current_user, 
                          role=role_name, 
                          sectors=sectors,
                          recent_logs=recent_logs)

# Admin routes
@app.route('/admin')
@login_required
@role_required('Agency Admin')
def admin_dashboard():
    # Get all users with their roles
    users = User.query.all()
    roles = Role.query.all()
    sectors = Sector.query.all()
    
    return render_template('admin_dashboard.html', 
                          users=users, 
                          roles=roles,
                          sectors=sectors)

@app.route('/admin/users/<int:user_id>/edit', methods=['GET', 'POST'])
@login_required
@permission_required('manage_roles')
def edit_user_role(user_id):
    user = User.query.get_or_404(user_id)
    
    if request.method == 'POST':
        role_id = request.form.get('role_id', type=int)
        sector_ids = request.form.getlist('sector_ids', type=int)
        
        # Update role
        old_role_id = user.role_id
        user.role_id = role_id
        
        # Update sectors - first remove all existing associations
        UserSector.query.filter_by(user_id=user.id).delete()
        
        # Add new sector associations
        for sector_id in sector_ids:
            user_sector = UserSector(user_id=user.id, sector_id=sector_id)
            db.session.add(user_sector)
            
        # Update the database
        db.session.commit()
        
        # Log the role change
        log_audit(current_user.id, 'update_role', 'success', 
               f"Changed {user.full_name}'s role from {old_role_id} to {role_id}", 
               request.remote_addr)
        
        flash(f'Updated {user.full_name}\'s role and sector access', 'success')
        return redirect(url_for('admin_dashboard'))
    
    roles = Role.query.all()
    sectors = Sector.query.all()
    user_sectors = [us.sector_id for us in UserSector.query.filter_by(user_id=user.id).all()]
    
    return render_template('edit_user_role.html', 
                          user=user, 
                          roles=roles,
                          sectors=sectors,
                          user_sectors=user_sectors)

# Sector-specific routes
@app.route('/sector/<sector_name>')
@login_required
def sector_dashboard(sector_name):
    # Check sector access directly in the route
    if not current_user.has_sector_access(sector_name):
        flash(f'You do not have access to the {sector_name} sector.', 'danger')
        return redirect(url_for('index'))
    # Get the sector
    sector = Sector.query.filter_by(name=sector_name).first_or_404()
    
    # Get users associated with this sector
    user_sectors = UserSector.query.filter_by(sector_id=sector.id).all()
    user_ids = [us.user_id for us in user_sectors]
    users = User.query.filter(User.id.in_(user_ids)).all() if user_ids else []
    
    if sector_name == 'Justice':
        # Get justice records
        records = JusticeRecord.query.all()
        return render_template('sectors/justice.html', sector=sector, users=users, records=records)
    
    elif sector_name == 'Banking':
        # Get banking records
        records = BankingRecord.query.all()
        return render_template('sectors/banking.html', sector=sector, users=users, records=records)
    
    elif sector_name == 'Humanitarian':
        # Get humanitarian records
        records = HumanitarianRecord.query.all()
        return render_template('sectors/humanitarian.html', sector=sector, users=users, records=records)
    
    elif sector_name == 'Voting':
        # Get voting records
        records = VotingRecord.query.all()
        return render_template('sectors/voting.html', sector=sector, users=users, records=records)
    
    elif sector_name == 'ID Card':
        # Get ID card records
        records = IdCardRecord.query.all()
        return render_template('sectors/id_card.html', sector=sector, users=users, records=records)
    
    elif sector_name == 'Transportation':
        # Get transportation records
        records = TransportationRecord.query.all()
        return render_template('sectors/transportation.html', sector=sector, users=users, records=records)
    
    # Generic sector view for any new sectors
    return render_template('sectors/generic.html', sector=sector, users=users)

# Print database URL (for debugging)
logging.debug(f"Using database URL: {app.config['SQLALCHEMY_DATABASE_URI'].split('@')[0]}@...hidden...")
