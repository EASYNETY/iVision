import os
import logging
import cv2
import numpy as np
from flask import Flask, request, render_template, jsonify, flash, redirect, url_for, session
import uuid
from datetime import datetime
from werkzeug.utils import secure_filename
from util.face_util import detect_faces, get_face_encoding, compare_faces
from werkzeug.security import generate_password_hash
from models import db, User, AuditLog

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

# Create upload directory if it doesn't exist
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB limit

# Allowed file extensions
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}

# Create database tables
with app.app_context():
    db.create_all()

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
    has_biometric_consent = data.get('has_biometric_consent') == 'true'
    has_data_storage_consent = data.get('has_data_storage_consent') == 'true'
    terms_accepted = data.get('terms_accepted') == 'true'
    
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
        
        # Create new user
        new_user = User(
            user_id=unique_id,
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
            device_type=request.user_agent.platform if request.user_agent else None
        )
        
        # Set the facial encoding
        new_user.set_facial_embedding(face_encoding)
        
        # Save to database
        db.session.add(new_user)
        db.session.commit()
        
        # Log the registration
        log_audit(unique_id, 'register', 'success', f"User {full_name} registered", request.remote_addr)
        
        logging.debug(f"Registered user: {full_name}")
        
        return jsonify({
            'success': True, 
            'message': f'User {full_name} registered successfully!',
            'user_id': unique_id
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
            
            # Return user data
            user_data = {
                'full_name': match.full_name,
                'user_id': match.user_id
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
        users = User.query.all()
        user_list = [{
            "id": user.user_id,
            "name": user.full_name,
            "email": user.email,
            "registration_date": user.registration_date.strftime('%Y-%m-%d %H:%M:%S') if user.registration_date else None
        } for user in users]
        
        return jsonify({'success': True, 'users': user_list})
    except Exception as e:
        logging.error(f"Error listing users: {e}")
        return jsonify({'success': False, 'message': 'Database error occurred while fetching users'}), 500

@app.route('/user/<user_id>', methods=['GET'])
def get_user(user_id):
    try:
        user = User.query.filter_by(user_id=user_id).first()
        
        if not user:
            return jsonify({'success': False, 'message': 'User not found'}), 404
        
        user_data = {
            "id": user.user_id,
            "full_name": user.full_name,
            "email": user.email,
            "phone_number": user.phone_number,
            "dob": user.dob.strftime('%Y-%m-%d') if user.dob else None,
            "gender": user.gender,
            "nationality": user.nationality,
            "address": user.address,
            "registration_date": user.registration_date.strftime('%Y-%m-%d %H:%M:%S') if user.registration_date else None,
            "last_identification": user.last_identification.strftime('%Y-%m-%d %H:%M:%S') if user.last_identification else None
        }
        
        return jsonify({'success': True, 'user': user_data})
    except Exception as e:
        logging.error(f"Error getting user: {e}")
        return jsonify({'success': False, 'message': 'Database error occurred while fetching user'}), 500

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

# Print database URL (for debugging)
logging.debug(f"Using database URL: {app.config['SQLALCHEMY_DATABASE_URI'].split('@')[0]}@...hidden...")
