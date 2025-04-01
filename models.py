from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import numpy as np
import json
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

class Role(db.Model):
    """Role model for RBAC"""
    __tablename__ = 'roles'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)  # Admin, Agency User, Viewer
    description = db.Column(db.String(255), nullable=True)
    
    # Relationships
    users = db.relationship('User', backref='role', lazy='dynamic')
    
    def __repr__(self):
        return f'<Role {self.name}>'

class Sector(db.Model):
    """Sector model for different modules (Justice, Banking, etc.)"""
    __tablename__ = 'sectors'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)  # Justice, Banking, Humanitarian, etc.
    description = db.Column(db.String(255), nullable=True)
    
    # Relationships
    users = db.relationship('UserSector', backref='sector', lazy='dynamic')
    
    def __repr__(self):
        return f'<Sector {self.name}>'

class Permission(db.Model):
    """Permission model for specific actions within the system"""
    __tablename__ = 'permissions'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)  # create_user, view_records, etc.
    description = db.Column(db.String(255), nullable=True)
    
    # Many-to-many relationship with roles
    roles = db.relationship('RolePermission', backref='permission', lazy='dynamic')
    
    def __repr__(self):
        return f'<Permission {self.name}>'

class RolePermission(db.Model):
    """Association table between roles and permissions"""
    __tablename__ = 'role_permissions'
    
    id = db.Column(db.Integer, primary_key=True)
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'), nullable=False)
    permission_id = db.Column(db.Integer, db.ForeignKey('permissions.id'), nullable=False)
    
    # Add a unique constraint to avoid duplicates
    __table_args__ = (db.UniqueConstraint('role_id', 'permission_id', name='role_permission_uc'),)

class UserSector(db.Model):
    """Association table between users and sectors"""
    __tablename__ = 'user_sectors'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    sector_id = db.Column(db.Integer, db.ForeignKey('sectors.id'), nullable=False)
    
    # Add a unique constraint to avoid duplicates
    __table_args__ = (db.UniqueConstraint('user_id', 'sector_id', name='user_sector_uc'),)

class User(UserMixin, db.Model):
    """User model for storing user details, facial embeddings, and role-based access"""
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(36), unique=True, nullable=False)  # UUID format
    username = db.Column(db.String(64), unique=True, nullable=True)  # For login
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
    
    # RBAC related fields
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'), nullable=True)
    is_active = db.Column(db.Boolean, default=True)  # For account status
    
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
    
    # Relationships
    sectors = db.relationship('UserSector', backref='user', lazy='dynamic')
    
    def set_password(self, password):
        """Set the password hash"""
        self.password_hash = generate_password_hash(password)
        
    def check_password(self, password):
        """Check if password matches the hash"""
        if self.password_hash:
            return check_password_hash(self.password_hash, password)
        return False
    
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
        
    def has_permission(self, permission_name):
        """Check if user has a specific permission based on their role"""
        if not self.role:
            return False
            
        # Find all permissions for the user's role
        role_permissions = RolePermission.query.filter_by(role_id=self.role_id).all()
        permission_ids = [rp.permission_id for rp in role_permissions]
        
        # Check if the specified permission is in the user's permissions
        permission = Permission.query.filter_by(name=permission_name).first()
        if permission and permission.id in permission_ids:
            return True
            
        return False
        
    def has_sector_access(self, sector_name):
        """Check if user has access to a specific sector"""
        sector = Sector.query.filter_by(name=sector_name).first()
        if not sector:
            return False
            
        # Check if user is associated with this sector
        user_sector = UserSector.query.filter_by(
            user_id=self.id, 
            sector_id=sector.id
        ).first()
        
        return user_sector is not None
    
    def __repr__(self):
        return f'<User {self.full_name}>'

class AuditLog(db.Model):
    """Enhanced audit log for recording system access and actions"""
    __tablename__ = 'audit_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    # Use Integer foreign key to match with User.id 
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)  # Can be null for anonymous attempts
    
    # Action information
    action = db.Column(db.String(100), nullable=False)  # e.g., "register", "identify", "login"
    action_type = db.Column(db.String(50), nullable=True)  # e.g., "Create", "Update", "Delete", "View"
    status = db.Column(db.String(50), nullable=False)  # e.g., "success", "failure"
    
    # Module/Section information
    module = db.Column(db.String(50), nullable=True)  # e.g., "Justice", "Banking", etc.
    
    # For data changes
    old_data = db.Column(db.Text, nullable=True)  # JSON string of old data (for updates/deletes)
    new_data = db.Column(db.Text, nullable=True)  # JSON string of new data (for creates/updates)
    
    # Additional details
    details = db.Column(db.Text, nullable=True)  # Additional details about the action
    ip_address = db.Column(db.String(50), nullable=True)
    device_info = db.Column(db.String(200), nullable=True)
    location = db.Column(db.String(200), nullable=True)  # Geographic location
    
    # Relationships
    user = db.relationship('User', backref=db.backref('audit_logs', lazy='dynamic'))
    
    def __repr__(self):
        return f'<AuditLog {self.action} by {self.user_id} at {self.timestamp}>'
        
    def set_old_data(self, data_dict):
        """Convert dict to JSON string for storage"""
        if data_dict:
            self.old_data = json.dumps(data_dict)
            
    def set_new_data(self, data_dict):
        """Convert dict to JSON string for storage"""
        if data_dict:
            self.new_data = json.dumps(data_dict)
            
    def get_old_data(self):
        """Convert JSON string back to dict"""
        if self.old_data:
            return json.loads(self.old_data)
        return None
        
    def get_new_data(self):
        """Convert JSON string back to dict"""
        if self.new_data:
            return json.loads(self.new_data)
        return None

# Sector-specific models
class JusticeRecord(db.Model):
    """Justice sector records for criminal history and law enforcement data"""
    __tablename__ = 'justice_records'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    # Criminal record information
    record_type = db.Column(db.String(50), nullable=False)  # e.g., "Arrest", "Conviction", "Investigation"
    record_date = db.Column(db.Date, nullable=False)
    case_number = db.Column(db.String(50), nullable=True)
    offense = db.Column(db.String(100), nullable=True)
    jurisdiction = db.Column(db.String(100), nullable=True)
    sentence = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(50), nullable=True)  # e.g., "Active", "Closed", "Pending"
    
    # Additional details
    details = db.Column(db.Text, nullable=True)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    user = db.relationship('User', backref=db.backref('justice_records', lazy='dynamic'))
    
    def __repr__(self):
        return f'<JusticeRecord {self.record_type} for User {self.user_id}>'

class BankingRecord(db.Model):
    """Banking sector records for financial history and transactions"""
    __tablename__ = 'banking_records'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    # Banking information
    account_number = db.Column(db.String(50), nullable=True)
    institution_name = db.Column(db.String(100), nullable=True)
    account_type = db.Column(db.String(50), nullable=True)  # e.g., "Checking", "Savings", "Credit"
    account_status = db.Column(db.String(50), nullable=True)  # e.g., "Active", "Closed", "Suspended"
    balance = db.Column(db.Float, nullable=True)
    currency = db.Column(db.String(10), default="USD")
    
    # Fraud detection flags
    is_fraudulent = db.Column(db.Boolean, default=False)
    fraud_details = db.Column(db.Text, nullable=True)
    
    # Additional details
    details = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    user = db.relationship('User', backref=db.backref('banking_records', lazy='dynamic'))
    
    def __repr__(self):
        return f'<BankingRecord {self.account_type} for User {self.user_id}>'

class HumanitarianRecord(db.Model):
    """Humanitarian sector records for aid distribution and eligibility"""
    __tablename__ = 'humanitarian_records'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    # Aid information
    aid_type = db.Column(db.String(50), nullable=False)  # e.g., "Food", "Medical", "Financial"
    distribution_date = db.Column(db.Date, nullable=True)
    organization = db.Column(db.String(100), nullable=True)
    aid_amount = db.Column(db.Float, nullable=True)
    aid_currency = db.Column(db.String(10), default="USD")
    
    # Eligibility information
    is_eligible = db.Column(db.Boolean, default=True)
    eligibility_criteria = db.Column(db.Text, nullable=True)
    
    # Additional details
    details = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    user = db.relationship('User', backref=db.backref('humanitarian_records', lazy='dynamic'))
    
    def __repr__(self):
        return f'<HumanitarianRecord {self.aid_type} for User {self.user_id}>'

class VotingRecord(db.Model):
    """Voting sector records for election participation and eligibility"""
    __tablename__ = 'voting_records'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    # Voting information
    is_registered = db.Column(db.Boolean, default=False)
    registration_date = db.Column(db.Date, nullable=True)
    district = db.Column(db.String(100), nullable=True)
    precinct = db.Column(db.String(50), nullable=True)
    
    # Election participation
    last_voted_date = db.Column(db.Date, nullable=True)
    last_election = db.Column(db.String(100), nullable=True)
    
    # Eligibility information
    is_eligible = db.Column(db.Boolean, default=True)
    eligibility_reason = db.Column(db.Text, nullable=True)
    
    # Additional details
    details = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    user = db.relationship('User', backref=db.backref('voting_records', lazy='dynamic'))
    
    def __repr__(self):
        return f'<VotingRecord for User {self.user_id}>'

class IdCardRecord(db.Model):
    """ID Card sector records for identity documentation"""
    __tablename__ = 'id_card_records'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    # ID Card information
    card_number = db.Column(db.String(50), nullable=False)
    card_type = db.Column(db.String(50), nullable=False)  # e.g., "National ID", "Driver's License", "Passport"
    issue_date = db.Column(db.Date, nullable=True)
    expiry_date = db.Column(db.Date, nullable=True)
    issuing_authority = db.Column(db.String(100), nullable=True)
    
    # Status information
    status = db.Column(db.String(50), default="Active")  # e.g., "Active", "Expired", "Revoked"
    status_reason = db.Column(db.Text, nullable=True)
    
    # Additional details
    details = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    user = db.relationship('User', backref=db.backref('id_card_records', lazy='dynamic'))
    
    def __repr__(self):
        return f'<IdCardRecord {self.card_type} for User {self.user_id}>'

class TransportationRecord(db.Model):
    """Transportation sector records for vehicle registration and violations"""
    __tablename__ = 'transportation_records'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    # Vehicle information
    vehicle_type = db.Column(db.String(50), nullable=True)  # e.g., "Car", "Motorcycle", "Truck"
    license_plate = db.Column(db.String(20), nullable=True)
    make = db.Column(db.String(50), nullable=True)
    model = db.Column(db.String(50), nullable=True)
    year = db.Column(db.Integer, nullable=True)
    
    # Registration information
    registration_number = db.Column(db.String(50), nullable=True)
    registration_date = db.Column(db.Date, nullable=True)
    expiry_date = db.Column(db.Date, nullable=True)
    
    # Violation information
    has_violations = db.Column(db.Boolean, default=False)
    violation_details = db.Column(db.Text, nullable=True)
    
    # Additional details
    details = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    user = db.relationship('User', backref=db.backref('transportation_records', lazy='dynamic'))
    
    def __repr__(self):
        return f'<TransportationRecord {self.vehicle_type} for User {self.user_id}>'