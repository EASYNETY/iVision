from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import numpy as np
import json

db = SQLAlchemy()

class User(db.Model):
    """User model for storing user details and facial embeddings"""
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(36), unique=True, nullable=False)  # UUID format
    full_name = db.Column(db.String(100), nullable=False)
    dob = db.Column(db.Date, nullable=True)
    gender = db.Column(db.String(20), nullable=True)
    nationality = db.Column(db.String(50), nullable=True)
    government_id = db.Column(db.String(50), nullable=True)
    
    # Contact information
    email = db.Column(db.String(100), nullable=True)
    phone_number = db.Column(db.String(20), nullable=True)
    address = db.Column(db.String(200), nullable=True)
    
    # Facial data
    facial_embedding = db.Column(db.Text, nullable=False)  # JSON string of facial features
    image_path = db.Column(db.String(200), nullable=False)  # Path to the original face image
    
    # Consent and authentication
    has_biometric_consent = db.Column(db.Boolean, default=False)
    has_data_storage_consent = db.Column(db.Boolean, default=False)
    terms_accepted = db.Column(db.Boolean, default=False)
    
    # Security and registration data
    password_hash = db.Column(db.String(256), nullable=True)
    registration_date = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Device information
    device_id = db.Column(db.String(100), nullable=True)
    device_type = db.Column(db.String(50), nullable=True)
    ip_address = db.Column(db.String(50), nullable=True)
    
    # Location information
    latitude = db.Column(db.Float, nullable=True)
    longitude = db.Column(db.Float, nullable=True)
    
    # Additional profile data
    occupation = db.Column(db.String(100), nullable=True)
    profile_photo_path = db.Column(db.String(200), nullable=True)
    
    # For law enforcement or security use
    is_suspect = db.Column(db.Boolean, default=False)
    known_alias = db.Column(db.String(100), nullable=True)
    criminal_record = db.Column(db.Text, nullable=True)
    
    # Audit data
    last_login = db.Column(db.DateTime, nullable=True)
    last_identification = db.Column(db.DateTime, nullable=True)
    
    def set_facial_embedding(self, embedding_array):
        """Convert numpy array to JSON string for storage"""
        if isinstance(embedding_array, np.ndarray):
            self.facial_embedding = json.dumps(embedding_array.tolist())
        else:
            self.facial_embedding = json.dumps(embedding_array)
    
    def get_facial_embedding(self):
        """Convert JSON string back to numpy array"""
        embedding_list = json.loads(self.facial_embedding)
        return np.array(embedding_list)

class AuditLog(db.Model):
    """Audit log for recording system access and actions"""
    __tablename__ = 'audit_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.String(36), nullable=True)  # Can be null for anonymous attempts
    action = db.Column(db.String(100), nullable=False)  # e.g., "register", "identify", "login"
    status = db.Column(db.String(50), nullable=False)  # e.g., "success", "failure"
    details = db.Column(db.Text, nullable=True)  # Additional details about the action
    ip_address = db.Column(db.String(50), nullable=True)
    device_info = db.Column(db.String(200), nullable=True)