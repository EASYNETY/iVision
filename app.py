import os
import logging
import cv2
import numpy as np
from flask import Flask, request, render_template, jsonify, flash, redirect, url_for, session
import uuid
from werkzeug.utils import secure_filename
from util.face_util import detect_faces, get_face_encoding, compare_faces

# Configure logging
logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "facial-recognition-secret-key")

# Create upload directory if it doesn't exist
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB limit

# Allowed file extensions
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}

# In-memory database for storing face encodings
# In a production environment, this would be a persistent database
users_db = {}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['POST'])
def register():
    if 'image' not in request.files:
        return jsonify({'success': False, 'message': 'No image file provided'}), 400
    
    file = request.files['image']
    name = request.form.get('name', '').strip()
    
    if not name:
        return jsonify({'success': False, 'message': 'Name is required'}), 400
    
    if file.filename == '':
        return jsonify({'success': False, 'message': 'No image selected'}), 400
    
    if not allowed_file(file.filename):
        return jsonify({'success': False, 'message': 'Invalid file type. Only PNG, JPG, and JPEG are allowed'}), 400
    
    # Save the uploaded file with a secure filename
    filename = secure_filename(file.filename)
    unique_filename = f"{uuid.uuid4()}_{filename}"
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
    
    # Store user data
    users_db[name] = {
        'name': name,
        'encoding': face_encoding,
        'image_path': file_path
    }
    
    logging.debug(f"Registered user: {name}")
    
    return jsonify({'success': True, 'message': f'User {name} registered successfully!'}), 200

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
    
    # Compare with stored encodings
    if not users_db:
        os.remove(file_path)  # Clean up
        return jsonify({'success': False, 'message': 'No registered users to compare with'}), 404
    
    # Try to find a match
    match = None
    for name, data in users_db.items():
        if compare_faces(data['encoding'], face_encoding):
            match = name
            break
    
    os.remove(file_path)  # Clean up
    
    if match:
        return jsonify({'success': True, 'message': f'Match found: {match}'}), 200
    else:
        return jsonify({'success': False, 'message': 'No match found'}), 404

@app.route('/users', methods=['GET'])
def list_users():
    user_list = [{"name": name} for name in users_db.keys()]
    return jsonify({'success': True, 'users': user_list})

@app.route('/reset', methods=['POST'])
def reset_database():
    users_db.clear()
    return jsonify({'success': True, 'message': 'Database reset successful'})

# Error handlers
@app.errorhandler(413)
def request_entity_too_large(error):
    return jsonify({'success': False, 'message': 'File too large. Maximum size is 16MB'}), 413

@app.errorhandler(500)
def internal_server_error(error):
    return jsonify({'success': False, 'message': 'Internal server error'}), 500
